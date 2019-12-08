package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Println(os.Getpid())

	j := 3

	for time.Since(time.Now()) < 1*time.Second {
		for i := 1; i < 1000000; i++ {
			j *= i
		}
	}
}
