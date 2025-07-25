package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type alarm struct {
	ID      bson.ObjectID `json:"id" bson:"_id,omitempty"`
	OwnerID bson.ObjectID `json:"ownerid" bson:"ownerid,omitempty"`
	Hours   int           `json:"hours"`
	Minutes int           `json:"minutes"`
	Seconds int           `json:"seconds"`
	Ampm    int           `json:"ampm"`
	Days    []int         `json:"days"`
}

type user struct {
	ID            bson.ObjectID `json:"_id" bson:"_id,omitempty"`
	Email         string        `json:"email"`
	Username      string        `json:"username"`
	CleanUsername string        `json:"cleanUsername" bson:"cleanUsername"`
	Password      string        `json:"password"`
	Times         []alarm       `json:"times"`
}

type userResponse struct {
	LoggedIn bool    `json:"loggedIn"`
	Email    string  `json:"email"`
	Username string  `json:"username"`
	Times    []alarm `json:"times"`
}

type dummyResponse struct {
	LoggedIn bool    `json:"loggedIn"`
	Username string  `json:"username"`
	Times    []alarm `json:"times"`
}

type errorResponse struct {
	Error    string `json:"error"`
	LoggedIn bool   `json:"loggedIn"`
}

type authentication struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type handler struct {
	Users *mongo.Collection
	Times *mongo.Collection
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

var SECRET = os.Getenv("SECRET")

var store = sessions.NewCookieStore([]byte(SECRET))

func (handler *handler) login(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var i authentication
	decodeErr := decoder.Decode(&i)
	if decodeErr != nil {
		panic(decodeErr)
	}
	if i.Login == "" {
		res := errorResponse{"Login cannot be blank", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(i.Password) <= 7 {
		res := errorResponse{"Password minimum length is 8 characters", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(i.Password) >= 41 {
		res := errorResponse{"Password max length is 40 characters", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	var u user
	reEmail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if reEmail.MatchString(i.Login) == false {
		reUsername := regexp.MustCompile("@")
		if reUsername.MatchString(i.Login) == true {
			res := errorResponse{"Username cannot contain an @ symbol", false}
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(res)
			return
		}
		if len(i.Login) >= 21 {
			res := errorResponse{"Username max length is 20 characters", false}
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(res)
			return
		}
		usernameSearchErr := handler.Users.FindOne(context.Background(), bson.M{"cleanUsername": i.Login}).Decode(&u)
		if usernameSearchErr == mongo.ErrNoDocuments {
			res := errorResponse{"No user found for that username", false}
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(res)
			return
		}
	} else {
		if len(i.Login) >= 255 {
			res := errorResponse{"Email max length is 254 characters", false}
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(res)
			return
		}
		emailSearchErr := handler.Users.FindOne(context.Background(), bson.M{"email": i.Login}).Decode(&u)
		if emailSearchErr == mongo.ErrNoDocuments {
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
	var userTimes []alarm
	cursor, err := handler.Times.Find(context.Background(), bson.M{"ownerid": u.ID})
	if err == nil {
		cursor.All(context.Background(), &userTimes)
	}
	res := userResponse{true, u.Email, u.Username, userTimes}
	if userTimes == nil {
		res.Times = []alarm{}
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
	dummy := dummyResponse{false, "", []alarm{}}
	json.NewEncoder(w).Encode(dummy)
}

func (handler *handler) loginStatus(w http.ResponseWriter, r *http.Request) {
	writeHeaders(w)
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	if session.Values["id"] == nil {
		dummy := dummyResponse{false, "", []alarm{}}
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
	var t []alarm
	oid, _ := bson.ObjectIDFromHex(id)
	handler.Users.FindOne(context.Background(), bson.M{"_id": oid}).Decode(&u)
	cursor, _ := handler.Times.Find(context.Background(), bson.M{"ownerid": oid})
	cursor.All(context.Background(), &t)
	res := userResponse{true, u.Email, u.Username, []alarm{}}
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
	if u.Username == "" {
		res := errorResponse{"Username cannot be blank", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	u.CleanUsername = strings.ToLower(u.Username)
	if len(u.Password) <= 7 {
		res := errorResponse{"Password minimum length is 8 characters", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(u.Password) >= 41 {
		res := errorResponse{"Password max length is 40 characters", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(u.Email) >= 255 {
		res := errorResponse{"Email max length is 254 characters", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	reEmail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if reEmail.MatchString(u.Email) != true {
		res := errorResponse{"Please use a valid email", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(u.Username) >= 21 {
		res := errorResponse{"Username max length is 20 characters", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	reUsername := regexp.MustCompile("@")
	if reUsername.MatchString(u.Username) == true {
		res := errorResponse{"Username cannot contain an @ symbol", false}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(res)
		return
	}
	var i user
	err = handler.Users.FindOne(context.Background(), bson.M{"email": u.Email}).Decode(&i)
	if err == nil {
		res := errorResponse{"This email already has an account", false}
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(res)
		return
	}
	// handle logic to look for search username
	err = handler.Users.FindOne(context.Background(), bson.M{"cleanUsername": u.CleanUsername}).Decode(&i)
	if err == nil {
		res := errorResponse{"This username is already associated with an account. Please choose a different username", false}
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(u.Password) <= 7 {
		res := errorResponse{"Password must be at least 8 characters", false}
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(u.Password) >= 41 {
		res := errorResponse{"Password can't be greater than 40 characters", false}
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(res)
		return
	}
	u.ID = bson.NewObjectID()
	hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if hashErr != nil {
		panic(hashErr)
	}
	u.Password = string(hashedPassword)
	handler.Users.InsertOne(context.Background(), u)
	session, sessionErr := store.Get(r, "User")
	if sessionErr != nil {
		panic(sessionErr)
	}
	session.Values["id"] = u.ID.Hex()
	session.Save(r, w)
	res := userResponse{true, u.Email, u.Username, []alarm{}}
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
	oid, _ := bson.ObjectIDFromHex(id)
	handler.Users.DeleteOne(context.Background(), bson.M{"_id": oid})
	// delete session
	res := userResponse{false, "", "", []alarm{}}
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
	var t alarm
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&t)
	// logic to check if time already exists
	var oldTimes []alarm
	oid, _ := bson.ObjectIDFromHex(id)
	cursor, _ := handler.Times.Find(context.Background(), bson.M{"ownerid": oid})
	cursor.All(context.Background(), &oldTimes)
	for _, oldTime := range oldTimes {
		if oldTime.Hours == t.Hours && oldTime.Minutes == t.Minutes && oldTime.Seconds == t.Seconds && oldTime.Ampm == t.Ampm {
			res := errorResponse{"Time already exists. If you want to change the days, please edit the original time", true}
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(res)
			return
		}
	}
	t.OwnerID = oid
	t.ID = bson.NewObjectID()
	_, insertErr := handler.Times.InsertOne(context.Background(), t)
	if insertErr != nil {
		panic(insertErr)
	}
	var userTimes []alarm
	cursor, searchErr := handler.Times.Find(context.Background(), bson.M{"ownerid": oid})
	if searchErr == nil {
		cursor.All(context.Background(), &userTimes)
	}
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
	var t alarm
	json.NewDecoder(r.Body).Decode(&t)
	var allTimes []alarm
	oid, _ := bson.ObjectIDFromHex(id)
	cursor, allSearchErr := handler.Times.Find(context.Background(), bson.M{"ownerid": oid})
	if allSearchErr != nil {
		panic(allSearchErr)
	}
	cursor.All(context.Background(), &allTimes)
	for _, oldTime := range allTimes {
		if oldTime.Hours == t.Hours && oldTime.Minutes == t.Minutes && oldTime.Seconds == t.Seconds && oldTime.Ampm == t.Ampm && oldTime.ID != t.ID {
			res := errorResponse{"Time already exists. If you want to change the days, please edit the original time", true}
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(res)
			return
		}
	}
	var origtime alarm
	searchErr := handler.Times.FindOne(context.Background(), bson.M{"_id": t.ID}).Decode(&origtime)
	if searchErr != nil {
		panic(searchErr)
	}
	// Verify that the person with the cookie is the owner of the time
	if id == origtime.OwnerID.Hex() {
		t.OwnerID = origtime.OwnerID
		handler.Times.ReplaceOne(context.Background(), bson.M{"_id": t.ID}, t)
		var times []alarm
		cursor, _ := handler.Times.Find(context.Background(), bson.M{"ownerid": oid})
		cursor.All(context.Background(), &times)
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
	var t alarm
	decoder.Decode(&t)
	oid, _ := bson.ObjectIDFromHex(id)
	var origtime alarm
	searchErr := handler.Times.FindOne(context.Background(), bson.M{"_id": t.ID}).Decode(&origtime)
	if searchErr != nil {
		panic(searchErr)
	}
	// Verify that the person with the cookie is the owner of the time
	if id == origtime.OwnerID.Hex() {
		handler.Times.DeleteOne(context.Background(), bson.M{"_id": t.ID})
		var times []alarm
		cursor, _ := handler.Times.Find(context.Background(), bson.M{"ownerid": oid})
		cursor.All(context.Background(), &times)
		if times == nil {
			times = []alarm{}
		}
		json.NewEncoder(w).Encode(times)
	} else {
		// The person removing the time doesn't have a matching cookie ID, send error
		json.NewEncoder(w).Encode(errorResponse{"You don't own this time", true})
	}
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB
	client, err := mongo.Connect(options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Connected to MongoDB \n")
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			log.Fatal(err)
		}
	}()

	// Ping the database
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal(err)
	}

	database := client.Database("clock")
	users := database.Collection("users")
	times := database.Collection("times")
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

	log.Println("Server starting on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}
