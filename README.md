ruby-SSLscanner
===============

A simple and easy to use SSL Cipher scanner


```bash
Usage: sslscanner.rb: [-s <server hostname/ip>] [-p <port>] [-d <debug>] [-c <certificate information>] [-o <output file>] [-t <output file type>]
```
TO-DO
=============
- [ ] More check for vulnerable cipher combinations
- [ ] Checks for insecured TLS renogotiation
- [ ] Checks for:
  - [ ] Heartbleed
  - [ ] Crime 
  - [ ] BEAST
- [ ] Checks for weak certificate key algorithms
- [ ] Option to import hosts from file
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
