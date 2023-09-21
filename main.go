package main

import (
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"
)


type person struct{
	First string
}

var db = map[string][]byte{}

func main(){
	http.HandleFunc("/", Index)
	http.HandleFunc("/register", Register)
	http.ListenAndServe(":8080", nil)
}

func Index(w http.ResponseWriter , r *http.Request){

}


func Register(w http.ResponseWriter , r *http.Request){
	if r.Method != http.MethodPost{
		errorMsg := url.QueryEscape("your method is not correct")
		http.Redirect(w , r , "/errormsg = "+errorMsg , http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		errorMsg := url.QueryEscape("your Email needs to not be empty")
		http.Redirect(w ,r , "/?errormsg="+errorMsg ,http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		errorMsg := url.QueryEscape("your Password needs to not be empty")
		http.Redirect(w ,r , "/?errormsg="+errorMsg ,http.StatusSeeOther)
		return
	}

	bsp,err := bcrypt.GenerateFromPassword([]byte(p) , bcrypt.DefaultCost)
	if err != nil{
		errorMsg := url.QueryEscape("there are an internal server error.--")
		http.Redirect(w , errorMsg , http.StatusInternalServerError)
		return
	}

	log.Println("Password ", p)
	log.Println("bcrypted ", bsp)
	db[e] =bsp

	http.Redirect(w ,r, "/" , http.StatusSeeOther)
}