# gocrack
A simple tool to automate password cracking with aircrack-ng

## Purpose
This tool is used to mass-crack WPA passphrases from handshake capture files.
Simply point `gocrack` to a directory containing handshake PCAP files, give it as many wordlists as you wish and let it work.

## Usage

The following flags are supported by gocrack:

    -input string
        Path to a directory containg handshake files
    
    -verbose
        Be verbose
    
    -wordlist value
        A wordlist path

## Example
    ./gocrack -input /home/user/handshakes/ -wordlist /home/user/wordlists/wordlist1.txt -wordlist /home/user/wordlists/wordlist2.txt -verbose

## Dependencies
Let's face it, colored output is awesome! So you'll need `aurora` in order to make this work.

    go get -u github.com/logrusorgru/aurora

After that you should be good to go.

# Disclaimer
This tool is for educational purposes only! Do not attempt to crack WiFi passphrases for networks that you do not own! Make sure the network owner consents to you attempting to crack the password.

In short: don't be evil, don't do anything illegal with this tool.

# Contribute
This is a quick-and-dirty tool that I created mainly because I wanted to learn some golang. So there are probably lots of inefficient lines in there, probably a lot of mistakes as well. 

If you want to make this tool better, feel free to create a pull request.