CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build 
cp lazyxds /usr/local/bin/lazyxds
docker build -f docekrfile -t registry.ushareit.me/sgt/lazyxds:v1 .
docker push registry.ushareit.me/sgt/lazyxds:v1
