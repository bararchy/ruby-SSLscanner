ruby-SSLscanner
===============

A simple and easy to use SSL Cipher scanner


```bash
Usage: sslscanner.rb: [-s <server hostname/ip>] [-p <port>] [-d <debug>] [-c <certificate information>] [-o <output file>] [-t <output file type>]
```

Added the '-h' option to allow importing a hosts file, the host file should have a server:port for each line.

TO-DO
=============
- [ ] More check for vulnerable cipher combinations
- [x] Checks for insecured TLS renogotiation
- [ ] Checks for:
  - [ ] Heartbleed
  - [x] Crime 
- [x] Checks for weak certificate key algorithms
- [x] Option to import hosts from file
  - [ ] multithreading when scanning multiple hosts
- [ ] Option to export data to file:
  - [x] txt
  - [ ] pdf
  - [ ] html
  - [ ] csv
- [ ] Some kind of a nice "loading bar" while results are geathred


[Licensed under GPLv3](license.txt)

Special thanks to:
* @ik5 (idokan@gmail.com).
* Dor Lerner (dorl3rn3r@gmail.com).
* @elichai 
