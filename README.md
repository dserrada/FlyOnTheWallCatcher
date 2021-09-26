# Fly On The Wall Catcher
_Fly On The Wall Catcher_ is a **Man in the Middle** detector, written in Java.

## Introduction
The main goal of this project is to create an open source tool, written in Java, that allow users/developers detect eavesdropping atacks on remote https connections.
The second goal is just to get a little fun writing code.

This work is inspired on the following document of Gibson Research Corporation ( https://www.grc.com/fingerprints.htm)

## RoadMap / Backlog
A list of future, and maybe one day real, features or things to do:

### Security
* Detection of forged certificates based on certificate fingerprint
* Detection of attempts to downgrade connection protocol version to enable other types of attacks.
* Checking of certificate chain (is really neccesary? or already done?)
* Checking of domain 
* Is important to check if certificate chain is pinned or not?
* Check obsolete protocols or algoritms.
* Store certificate and connection properties to check in a secure way ¿how? ¿distributed?
* Rest API
  *  Simple Web App, using Spring Boot, that show cert info obtained from the server where the web app is deployed.
  *  Simple consumer, in Java and Javascript clients, who compares the cert info get by the web server and the one's get by the program.
* Test, tests, and more tests

### Build
* Use jpackage to distribute application.
* Upgrade to use jdk 17 when available
* Seal the classes... ¿not very important?
* Automatic generation of pom.xml to help GitHub detecting dependencies

### Other types of eavesdropping detection
* Change of gateway via a network card on LAN in promiscuous mode. 

## Next sprint
Goal: Store cert info in the local system.
Due Date: who knows when... :-) 
