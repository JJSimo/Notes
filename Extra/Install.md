# Go
- download from [here](https://go.dev/dl/) the latest tar
- `sudo tar -C /usr/local -xvf ARCHIVE.tar.gz`
- `sudo vi ~/.profile`
- add as last line -->  `export PATH=$PATH:/usr/local/go/bin`
- quit and -->  `source ~/.profile`
- check with -->  `go version`
 
## Install the latest
- download from [here](https://go.dev/dl/) the latest tar
- `sudo rm -r /usr/local/go/`
- `sudo rm -r /usr/bin/go`
- `sudo tar -xvf ARCHIVE.tar.gz`
- `sudo mv go/ /usr/local`
- `sudo vi ~/.profile`
- add as last line -->  `export PATH=$PATH:/usr/local/go/bin`
- quit and -->  `source ~/.profile`

# Docker
`sudo apt install docker.io`                  -->  `check with docker --version`
`sudo apt install docker-compose`         -->  `check with docker-compose --version`

