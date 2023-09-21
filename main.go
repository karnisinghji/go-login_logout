package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type person struct {
	First string
}

// key is email , value is password
var db = map[string][]byte{}
var sessions = map[string]string{}

//var tpl *template.Template

var key = []byte("the sucess of mine is the blessing of my Guruji shri shri 1008 ShriNiwas Prasad Sir")

/* func init() {
	tpl = template.Must(template.ParseGlob("tmp/*"))
} */

func main() {
	http.HandleFunc("/", Index)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.ListenAndServe(":8080", nil)
}

func Index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	s, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken ", err)
	}
	var e string
	if s != "" {
		e = sessions[s]
	}

	/* r.ParseForm()
	tpl.ExecuteTemplate(w , "tmp.html" , nil) */
	msg := r.FormValue("msg")

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html>
	<head>
		<meta charset='utf-8'>
		<meta http-equiv='X-UA-Compatible' content='IE=edge'>
		<title>Page Title</title>
		<meta name='viewport' content='width=device-width, initial-scale=1'>
		<link rel='stylesheet' type='text/css' media='screen' href='main.css'>
		<script src='main.js'></script>
	</head>
	<body>
	<h2>If THERE WAS ANY ERROR , HERE IT IS : %s</h1>
		<form action="register" method="post">
		<h2><b>Registration </h2>
			Email<input type="email" name="e">
			Password<input type="password" name="p">
			<input type="submit">
		</form>
	
		 <form action="login" method="post">
		<h2><b>Log In </h2>
			Email<input type="email" name="e">
			Password<input type="password" name="p">
			<input type="submit">
	
		</form>
		
	</body>
	</html>`, e, msg)

}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method is not correct")
		http.Redirect(w, r, "/msg = "+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your Email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your Password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	bsp, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		msg := url.QueryEscape("there are an internal server error.--")
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	log.Println("Password :->", p)
	log.Println("bcrypted password :->", bsp)
	db[e] = bsp

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/msg = "+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your Email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your Password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[e]; !ok {
		msg := url.QueryEscape("your email and password did't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword((db[e]), []byte(p))
	if err != nil {
		msg := url.QueryEscape("your email and password did't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	sUUID := uuid.New().String()
	sessions[sUUID] = e
	token := createToken(sUUID)

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
	}
	http.SetCookie(w, &c)

	msg := url.QueryEscape("you logged in " + e)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func createToken(sid string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sid))

	// to get in hex
	// signedMac := fmt.Sprintf("%x" , mac.Sum(nil))

	// to base 64
	signedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// signedSessionId as base64  |  created from sid
	return signedMac + "|" + sid
}

func parseToken(ss string) (string, error) {
	xs := strings.SplitN(ss, "|", 2)
	if len(xs) != 2 {
		return "", fmt.Errorf("wrong number of item in string parseToken")
	}

	// signedSession as base64 | created from sid
	b64 := xs[0]
	xb, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("couldn't parseToken decodestring %w", err)
	}

	// SIGNEDSESSIONID AS BASE64 |CREATED FORM SID
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(xs[1]))

	ok := hmac.Equal(xb, mac.Sum(nil))
	if !ok {
		return "", fmt.Errorf("couldn't parseToken not equal signed sid and sid")
	}
	return xs[1], nil
}
