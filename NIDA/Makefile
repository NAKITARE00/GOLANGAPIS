default: build run

build:
	go build -v -o bin/nida .

run:
	./bin/nida

win64:
	GOOS=windows GOARCH=amd64 go build -v -o bin/nida.exe .
