package main

import (	
	"fmt"
	"encoding/json"
	"log"
)


type person struct{
	First string
}
 
func main(){

p1 := person{
First:"ajay",
}
p2:= person{
	First: "Ravi",
}
xp:=[] person{p1,p2}

bs, err := json.Marshal(xp)
if err != nil{
	log.Panic(err)
}
fmt.Println(string(bs))

}