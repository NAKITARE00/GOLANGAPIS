package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

type User struct {
	NIN string `json:"nin"`

}

type Question struct {
	NIN string `json:"nin"`
	Question string `json:"question"`
}

type Answer struct {
	NIN string `json:"nin"`
	Answer string `json:"answer"`
}

type Results struct {
	NIN string `json:"nin"`
	Results string `json:"results"`
}

func reqQuestions(w http.ResponseWriter, r *http.Request){}

func recQuestions(w http.ResponseWriter, r *http.Request){}

func retAnswers(w http.ResponseWriter, r *http.Request){
	getResults()
}

func getResults(){}

func main(){
	router := mux.NewRouter()
	router.HandleFunc("/user", reqQuestions).Methods("POST")
	router.HandleFunc("/verification", recQuestions).Methods("GET")
	router.HandleFunc("/results", retAnswers).Methods("GET")
}
