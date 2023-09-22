package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Password []byte
	First    string
}
type customClaims struct {
	jwt.StandardClaims
	SID string
}

// key is email , value is password
//new :key is email , value is user

var db = map[string]user{}
var sessions = map[string]string{}

var tpl *template.Template

var key = []byte("the sucess of mine is the blessing of my Guruji shri shri 1008 ShriNiwas Prasad Sir")

func init() {
	tpl = template.Must(template.ParseGlob("tmp/*"))
}

func main() {
	http.HandleFunc("/", Index)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", logout)
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

	SID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken ", err)
	}
	var e string
	if SID != "" {
		e = sessions[SID]
	}

	var f string
	if user, ok := db[e]; ok {
		f = user.First
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
	<h2>IF YOU HAVE A SESSION , HERE IS YOUR NAME : %S</h2>
	<h2>IF YOU HAVE A SESSION , HERE IS YOUR EMAIL : %S</h2>
	<h2>If THERE WAS ANY ERROR , HERE IT IS : %s</h1>
		<form action="register" method="post">
		<h2><b>Registration </h2>
		<label for="first">First</label>
		First<input type="text" name="first" id="first" placeholder="first">
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
		<h1>Logout</h1>
		<form actioon="/logout" method="POST">
		<input type="submit" vale="logout">
		</form>
	</body>
	</html>`, f, e, msg)

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

	f := r.FormValue("first")
	if f == "" {
		msg := url.QueryEscape("your first name to not be empty")
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
	db[e] = user{
		Password: bsp,
		First:    f,
	}

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

	err := bcrypt.CompareHashAndPassword((db[e].Password), []byte(p))
	if err != nil {
		msg := url.QueryEscape("your email and password did't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	sUUID := uuid.New().String()
	sessions[sUUID] = e
	token, err := createToken(sUUID)
	if err != nil {
		log.Println("couldn't createToken in Login ", err)
		msg := url.QueryEscape("our server didn't get response at this time, plz try after some time")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
	}
	http.SetCookie(w, &c)

	msg := url.QueryEscape("you logged in " + e)
	//http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
	fmt.Fprintf(w,``)
	tpl.ExecuteTemplate(w, "welcome.html", msg)
}

func createToken(sid string) (string, error) {

	cc := customClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		SID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	st, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("could't sign token in createToken %w", err)
	}
	return st, nil
}

func parseToken(st string) (string, error) {

	token, err := jwt.ParseWithClaims(st, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims different algorithms used")
		}
		return key, nil
	})
	if err != nil {
		return "", fmt.Errorf("couldn't ParsewithClaims in parseToken %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parseToken")
	}

	return token.Claims.(*customClaims).SID, nil
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
		fmt.Println("cookie value in logout ",c.Value)

	}
	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken ", err)
	}

	delete(sessions, sID)
	c.MaxAge = -1
	http.SetCookie(w, c)
	fmt.Println("cookie value in logoutafter deletasion ",c.Value)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
