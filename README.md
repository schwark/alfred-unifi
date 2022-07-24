# alfred-unifi
Alfred  Workflow for interacting with Unifi controllers - not tested on UnifiOS controllers
## Install

* Download .workflow file from [Releases](https://github.com/schwark/alfred-unifi/releases)
* Can be installed from Packal at http://www.packal.org/workflow/unifi-controller-workflow
* Can also be downloaded from github as a zip file, unzip the downloaded zip, cd into the zip directory, and create a new zip with all the files in that folder, and then renamed to Smartthings.alfredworkflow
* Or you can use the workflow-build script in the folder, using
```
chmod +x workflow-build
./workflow-build . 
```

## Python Setup

Macs are not shipping with Python2 anymore, and this workflow needs it at least for now. So set this up...

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" # if you do not have Homebrew already
brew install pyenv
pyenv install 2.7.18
pyenv global 2.7.18
echo 'PATH=$(pyenv root)/shims:$PATH' >> ~/.zshrc
```

Also, after you install the workflow, you need to add this path as a user variable in the workflow on the first screen.

## Controller

```
uf ip <controller-ip>
```
This should only be needed once per install or after a reinit


## Credentials

```
uf upwd <username> <password>
```
This should only be needed once per install or after a reinit - stored securely in MacOS keychain

```
uf mfa <two-factor-code>
```
This is needed everytime before a login is made - that could be everytime the session times out, and the command fails

```
uf secret <totp-secret>
```
This should only be needed once per install or after a reinit if you use MFA - stored securely in MacOS keychain - if this is used, uf mfa should never be needed. Preferred way to use if you use two factor

## Device/Client/Icons Update

```
uf update
```
This should be needed once at the install, and everytime you want to refresh information on devices/clients - should happen automatically at least once a day

## Device Commands

```
uf <device-name> clients|reboot|upgrade
```

devices - are UniFi devices - switches, gateways, routers, APs, etc. search term can be alias, hostname or ip
* clients - gives you the list of clients attached to this device
* reboot - reboots device
* upgrade - upgrades device to latest firmware (items marked with a * in subtitle when upgradable)

## Client Commands

```
uf <client-name> reconnect|block|unblock
```

clients are endpoints that connect to the network. search term can be name or ip
* reconnect - forces the endpoint to reconnect to the network
* block - kicks the endpoint off the network, and prevents it from connecting
* unblock - undoes the above

## Radius Commands

```
uf <radius-account-name> 
```
Read-only at the moment - pulls up all radius accounts matching search term and some details on them. search term is the username

## Firewall Commands

```
uf <firewall-rule-name> enable|disable
```
Will enable or disable firewall rules by name. The status is not updated automatically, and uf update needs to be called to update the status of the devices and rules

## Update Frequency

```
uf freq <number-of-seconds>
```
This is an optional setting to change how frequently the clients and their status is updated. This takes a couple of seconds and so making it too small may be annoying, but it is a tradeoff between fresh data and speed of response. By default, this is updated once a day. A more aggressive but still usable setting is 3600 or every hour.

## Reinitialize

```
uf reinit
```
This should only be needed if you ever want to start again for whatever reason - removes all API keys, devices, scenes, etc.

## Update

```
uf workflow:update
```
An update notification should show up when an update is available, but if not invoking this should update the workflow to latest version on github

## Acknowledgements

Icons made by [Freepik](https://www.flaticon.com/authors/freepik) from [www.flaticon.com](https://www.flaticon.com)  
Icons made by [Good Ware](https://www.flaticon.com/authors/good-ware) from [www.flaticon.com](https://www.flaticon.com)  
Icons also from [IconFinder](https://www.iconfinder.com/)
