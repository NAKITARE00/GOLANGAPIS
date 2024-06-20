
package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.POST("/verify", verifyHandler)
	router.Run(":8080")
}
