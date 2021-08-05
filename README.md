# Fly On The Wall Catcher
_Fly On The Wall Catcher_ is a **Man in the Middle** detector, written in Java.

## Introduction
The main goal of this project is to create an open source tool, written in Java, that allow users/developers detect eavesdropping atacks on remote https connections.
The second goal is just to get a little fun writing code.

This work is inspired on the following document of Gibson Research Corporation ( https://www.grc.com/fingerprints.htm)


## RoadMap
A list of future, and maybe one day real, features.
* Detection of forged certificates based on certificate fingerprint
* Detection of attempts to downgrade connection version to enable other types of attacks.
* Checking of certificate chain
* Checking of domain 

Other types of eavesdropping detection:
* Change of gateway via a network card on LAN in promisucuous mode. 