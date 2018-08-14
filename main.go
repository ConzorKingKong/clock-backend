package main

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"regexp"
)

type time struct {
	ID      bson.ObjectId `json:"id" bson:"_id,omitempty"`
	OwnerID bson.ObjectId `json:"ownerid" bson:"ownerid,omitempty"`
	Hours   int           `json:"hours"`
	Minutes int           `json:"minutes"`
	Seconds int           `json:"seconds"`
	Ampm    int           `json:"ampm"`
	Days    []int         `json:"days"`
}

type user struct {
	ID       bson.ObjectId `json:"_id" bson:"_id,omitempty"`
	Email    string        `json:"email"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	Times    []time        `json:"times"`
}

type userResponse struct {
	LoggedIn bool   `json:"loggedIn"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Times    []time `json:"times"`
}

type dummyResponse struct {
	LoggedIn bool   `json:"loggedIn"`
	Times    []time `json:"times"`
}

type errorResponse struct {
	Error    string `json:"error"`
	LoggedIn bool   `json:"loggedIn"`
}

type handler struct {
	Users *mgo.Collection
	Times *mgo.Collection
}

func writeHeaders(w http.ResponseWriter) {
	headers := w.Header()
	headers.Add("Access-Control-Allow-Origin", "*")
	headers.Add("Vary", "Origin")
	headers.Add("Vary", "Access-Control-Request-Method")
	headers.Add("Vary", "Access-Control-Request-Headers")
	headers.Add("Access-Control-Allow-Headers", "Content-Type, Origin, Accept, token")
	headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	headers.Set("Content-Type", "application/json")
}

var store = sessions.NewCookieStore([]byte("poopies"))

func (handler *handler) login(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var i user
	decodeErr := decoder.Decode(&i)
	if decodeErr != nil {
		panic(decodeErr)
	}
	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	var u user
	if re.MatchString(i.Email) == false {
		usernameSearchErr := handler.Users.Find(bson.M{"username": i.Email}).One(&u)
		if usernameSearchErr != nil {
			res := errorResponse{"No user found for that username", false}
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(res)
			return
		}
	} else {
		emailSearchErr := handler.Users.Find(bson.M{"email": i.Email}).One(&u)
		if emailSearchErr != nil {
			res := errorResponse{"No user found for that email", false}
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(res)
			return
		}
	}
	hashErr := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(i.Password))
	if hashErr != nil {
		res := errorResponse{"Incorrect Password", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	session.Values["id"] = u.ID.Hex()
	sessionSaveErr := session.Save(r, w)
	if sessionSaveErr != nil {
		panic(sessionSaveErr)
	}
	res := userResponse{true, u.Email, u.Username, []time{}}
	var userTimes []time
	handler.Times.Find(bson.M{"ownerId": u.ID}).All(&userTimes)
	if userTimes != nil {
		res.Times = []time{}
	}
	json.NewEncoder(w).Encode(res)
}

func (handler *handler) logout(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	session.Values["id"] = nil
	session.Save(r, w)
	dummy := dummyResponse{false, []time{}}
	json.NewEncoder(w).Encode(dummy)
}

func (handler *handler) loginStatus(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	if session.Values["id"] == nil {
		dummy := dummyResponse{false, []time{}}
		json.NewEncoder(w).Encode(dummy)
		return
	}
	id, ok := session.Values["id"].(string)
	if !ok {
		res := errorResponse{"cookie of id is not type string", false}
		json.NewEncoder(w).Encode(res)
		return
	}
	var u user
	var t []time
	handler.Users.Find(bson.M{"_id": bson.ObjectIdHex(id)}).One(&u)
	handler.Times.Find(bson.M{"ownerid": bson.ObjectIdHex(id)}).All(&t)
	res := userResponse{true, u.Email, u.Username, []time{}}
	if t != nil {
		res.Times = t
	}
	json.NewEncoder(w).Encode(res)
}

func (handler *handler) newUser(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var u user
	err := decoder.Decode(&u)
	if err != nil {
		panic(err)
	}
	var i user
	handler.Users.Find(bson.M{"email": u.Email}).One(&i)
	if i.Email != "" {
		res := errorResponse{"This email already has an account", false}
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(res)
		return
	}
	handler.Users.Find(bson.M{"username": u.Username}).One(&i)
	if i.Username != "" {
		res := errorResponse{"This username is already associated with an account. Please choose a different username", false}
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(res)
		return
	}
	u.ID = bson.NewObjectId()
	hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if hashErr != nil {
		panic(hashErr)
	}
	u.Password = string(hashedPassword)
	handler.Users.Insert(u)
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	session.Values["id"] = u.ID.Hex()
	session.Save(r, w)
	res := userResponse{true, u.Email, u.Username, []time{}}
	json.NewEncoder(w).Encode(res)
}

func (handler *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	id, ok := session.Values["id"].(string)
	if !ok {
		json.NewEncoder(w).Encode(errorResponse{"You are not signed in", false})
	}
	handler.Users.Remove(bson.M{"_id": bson.ObjectIdHex(id)})
	res := userResponse{false, "", "", []time{}}
	json.NewEncoder(w).Encode(res)
}

func (handler *handler) newTime(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	id, ok := session.Values["id"].(string)
	if !ok {
		res := errorResponse{"owner ID was not string", false}
		json.NewEncoder(w).Encode(res)
		return
	}
	var t time
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&t)
	t.OwnerID = bson.ObjectIdHex(id)
	t.ID = bson.NewObjectId()
	insertErr := handler.Times.Insert(t)
	if insertErr != nil {
		panic(insertErr)
	}
	var userTimes []time
	searchErr := handler.Times.Find(bson.M{"ownerid": bson.ObjectIdHex(id)}).All(&userTimes)
	if searchErr != nil {
		panic(searchErr)
	}
	json.NewEncoder(w).Encode(userTimes)
}

func (handler *handler) editTime(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	id, ok := session.Values["id"].(string)
	if !ok {
		res := errorResponse{"owner ID was not string", false}
		json.NewEncoder(w).Encode(res)
		return
	}
	var t time
	json.NewDecoder(r.Body).Decode(&t)
	var origtime time
	searchErr := handler.Times.FindId(t.ID).One(&origtime)
	if searchErr != nil {
		panic(searchErr)
	}
	// Verify that the person with the cookie is the owner of the time
	if id == origtime.OwnerID.Hex() {
		t.OwnerID = origtime.OwnerID
		handler.Times.UpdateId(t.ID, t)
		var times []time
		handler.Times.Find(bson.M{"ownerid": bson.ObjectIdHex(id)}).All(&times)
		json.NewEncoder(w).Encode(times)
	} else {
		// The person removing the time doesn't have a matching cookie ID, send error
		json.NewEncoder(w).Encode(errorResponse{"You don't own this time", true})
	}

}

func (handler *handler) deleteTime(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	id, ok := session.Values["id"].(string)
	if !ok {
		res := errorResponse{"owner ID was not string", false}
		json.NewEncoder(w).Encode(res)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var t time
	decoder.Decode(&t)
	var origtime time
	searchErr := handler.Times.FindId(t.ID).One(&origtime)
	if searchErr != nil {
		panic(searchErr)
	}
	// Verify that the person with the cookie is the owner of the time
	if id == origtime.OwnerID.Hex() {
		handler.Times.Remove(bson.M{"_id": t.ID})
		var times []time
		handler.Times.Find(bson.M{"ownerid": bson.ObjectIdHex(id)}).All(&times)
		if times == nil {
			times = []time{}
		}
		json.NewEncoder(w).Encode(times)
	} else {
		// The person removing the time doesn't have a matching cookie ID, send error
		json.NewEncoder(w).Encode(errorResponse{"You don't own this time", true})
	}
}

func main() {
	session, connErr := mgo.Dial("mongodb://127.0.0.1/clock")
	if connErr != nil {
		panic(connErr)
	}
	defer session.Close()
	users := session.DB("clock").C("users")
	times := session.DB("clock").C("times")
	handler := &handler{users, times}

	http.Handle("/", http.FileServer(http.Dir("./public")))
	http.HandleFunc("/api/login", handler.login)
	http.HandleFunc("/api/logout", handler.logout)
	http.HandleFunc("/api/loginstatus", handler.loginStatus)
	http.HandleFunc("/api/newuser", handler.newUser)
	http.HandleFunc("/api/deleteuser", handler.deleteUser)
	http.HandleFunc("/api/newtime", handler.newTime)
	http.HandleFunc("/api/edittime", handler.editTime)
	http.HandleFunc("/api/deletetime", handler.deleteTime)
	http.ListenAndServe(":3000", nil)
}
