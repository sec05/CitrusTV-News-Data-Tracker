package main

import (
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"os"
	"context"
	"time"
)

type Database struct
{
	client *mongo.Client
	ctx context.Context
	cancel context.CancelFunc
}

func (database *Database) Connect() error {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	DB_URI := os.Getenv("DB_URI")

	ctx, cancel := context.WithTimeout(context.Background(),30*time.Second)

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(DB_URI))
	database.client = client
	database.ctx = ctx
	database.cancel = cancel
	return err

}
func (database *Database) Ping() error {

	if err := database.client.Ping(database.ctx, readpref.Primary()); err != nil {
		return err
	}
	log.Println("connected successfully")
	return nil
}

func (database Database) Close() {
	defer database.cancel()


    defer func(){

        if err := database.client.Disconnect(database.ctx); err != nil{
            panic(err)
        }
    }()
}

func (database *Database) InsertOne(doc interface{}) (*mongo.InsertOneResult, error) {
	collection := database.client.Database("CitrusTV-Data").Collection("VLAN1")
	result, err := collection.InsertOne(database.ctx,doc)
	return result,err
}
