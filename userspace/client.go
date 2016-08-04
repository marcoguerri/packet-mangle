package main

import (
        "net"
        "os"
        "fmt"
        "time"
        "syscall"
        "flag"
        "io/ioutil"
        "crypto/md5"
        )

var ip = flag.String("ip", "", "Server IP")
var port = flag.Int("port", 0, "Server port")
var payload_path = flag.String("payload", "", "Path of the payload to be sent")
var runs = flag.Int("runs", 1, "Number of times the payload should be send")

func check(e error) {
    if e != nil {
        fmt.Fprintf(os.Stderr, "\n%s", e)
    }
}


func main() {

    flag.Parse()
    
    if *ip == "" || *port == 0 || *payload_path == "" {
        fmt.Println("Error while parsing command line arguments. Usage:")
        flag.PrintDefaults()
        os.Exit(1)
    }

    ipaddr := net.ParseIP(*ip)
    if ipaddr == nil {
        fmt.Fprintf(os.Stderr, "IP address is not valid")
        os.Exit(1)
    }

    fmt.Printf("Contacting server at %s:%d\n", ipaddr.String(), *port)
    tcpaddr := net.TCPAddr{
                IP:   ipaddr,
                Port: *port,
    }

    var retry int = 3
    var curr_run int = *runs

    for {
        if curr_run == 0 {
            break
        }
        conn, err := net.DialTimeout("tcp", tcpaddr.String(), time.Duration(2 * time.Second))
        if err != nil {
                if operr, ok := err.(*net.OpError); ok {
                    if oserr, ok := operr.Err.(*os.SyscallError); ok {
                        if oserr.Err == syscall.ECONNREFUSED {
                            fmt.Fprintf(os.Stderr, "\nConnection refused. ")
                            retry -= 1
                            if retry == 0 {
                                fmt.Fprintf(os.Stderr, "Will not retry...\n")
                                os.Exit(1) 
                            }  
                            fmt.Fprint(os.Stderr, "Retrying...\n")
                            time.Sleep(2 * time.Second)
                            continue
                        }
                    }
                    /* Error, terminating. */
                    fmt.Fprintf(os.Stderr, "Error while connection to server: %s (%d)\n", operr.Err, operr.Err) 
                    os.Exit(1)
                }
                fmt.Fprintf(os.Stderr, "Error while connecting to server: %s\n", err)
                os.Exit(1)
        }

        /* Connection succeeded, reset retry counter */
        retry = 3

        /* Reading payload, calculating md5sum and sending everything off to the client */
        data, err := ioutil.ReadFile(*payload_path)
        check(err)
        checksum := md5.Sum(data)
        
        _, err = conn.Write(checksum[:])
        check(err)
        _, err = conn.Write(data)
        check(err)

        fmt.Fprintf(os.Stderr, "\rRun: %d", *runs - curr_run + 1)
        conn.Close()
        curr_run -= 1
    }
}
