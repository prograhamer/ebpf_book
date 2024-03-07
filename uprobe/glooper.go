package main

import (
	"fmt"
	"time"
)

type Message struct {
	msg string
}

func (m *Message) Print() {
	fmt.Println(m.msg)
}

func main() {
	m := Message{"hello, glooper"}
	for {
		m.Print()
		time.Sleep(time.Second)
	}
}
