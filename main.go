package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/gomail.v2"
	"gopkg.in/mgo.v2/bson"
)

func sendVerificationEmail(email string) {
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", "namdang020201@gmail.com")
	mailer.SetHeader("To", email)
	mailer.SetHeader("Subject", "Verify account")
	mailer.SetBody("text/html", "Congratulations! You have successfully registered an account")
	// Vui lòng click vào liên kết sau để xác nhận địa chỉ email của bạn: <a href='http://yourapp.com/verify?email="+email+"'>Xác nhận</a>

	dialer := gomail.NewDialer("smtp.gmail.com", 587, "namdang020201@gmail.com", "fnqz ugrw pdzl tgcx")

	if err := dialer.DialAndSend(mailer); err != nil {
		panic("Error send email: " + err.Error())
	}
}

var jwtKey = []byte("123")

type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.StandardClaims
}

func createToken(email string, role string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: email,
		Role:  role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func authMiddleware(name string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		fmt.Println(tokenString)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		token, err := jwt.ParseWithClaims(strings.Split(tokenString, " ")[1], &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized token not good", "token": token})
			c.Abort()
			return
		}
		if token == nil {
			return
		}
		claims, _ := token.Claims.(*Claims)
		i := claims.Role
		fmt.Println(claims)
		fmt.Println(i)
		fmt.Println(name)
		if strings.Contains(name, i) {
			fmt.Println("Role access")
		} else {
			fmt.Println("Role denied")
			c.Abort()
			return
		}
		// if name == i {
		// 	c.JSON(http.StatusOK, gin.H{"": "sss"})
		// } else {
		// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "permission denied"})
		// 	c.Abort()
		// 	return
		// }
		c.Next()
	}

	// if i == pass {
	// 	c.Next()
	// 	return
	// } else {
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized password is not"})
	// 	c.Abort()
	// 	return
	// }\
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, HEAD, PATCH, OPTIONS, GET, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

var collection *mongo.Collection

func init() {
	// Thiết lập thông tin kết nối MongoDB
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	// Lấy collection trong MongoDB
	collection = client.Database("DB-test").Collection("customer")
	// collection_admin = client.Database("DB-test").Collection("admin")

}

func handleData(c *gin.Context) {
	// Handle data request (can query MongoDB or any data source)
	c.JSON(http.StatusOK, gin.H{"data": "This is protected data"})
}

// func AuthMiddleware(role string) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		// Kiểm tra quyền của người dùng từ token hoặc session
// 		userRole := getUserRoleFromToken(c) // Hàm giả định để lấy quyền từ token

// 		// So sánh quyền của người dùng với quyền được yêu cầu
// 		if userRole != allowedRole {
// 			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
// 			c.Abort() // Dừng xử lý tiếp theo của yêu cầu
// 			return
// 		}

//			// Nếu người dùng có quyền, cho phép yêu cầu tiếp theo được xử lý
//			c.Next()
//		}
//	}
func main() { // Dữ liệu để thêm vào MongoDB
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// setup gin middleware
	r.Use(gin.Recovery())
	r.Use(CORSMiddleware())
	// Register
	r.POST("/register", func(c *gin.Context) {
		var person CustomerData

		if err := c.BindJSON(&person); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Lưu trữ dữ liệu người dùng vào MongoDB
		_, err := collection.InsertOne(context.TODO(), person)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		sendVerificationEmail(person.Email)
		{
			c.JSON(http.StatusOK, gin.H{"message": "Đăng ký thành công"})
		}
	})
	// Login
	r.POST("/login", func(c *gin.Context) {
		var loginData struct {
			Email    string `bson:"email" binding:"required"`
			Password string `bson:"password" `
			Role     string `bson:"role" `
		}

		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := collection.FindOne(context.TODO(), bson.M{"email": loginData.Email, "password": loginData.Password}).Decode(&loginData)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "Đăng nhập không thành công"})
			return
		} else {
			token, _ := createToken(loginData.Email, loginData.Role)
			c.JSON(http.StatusOK, gin.H{"token": token,
				"role": loginData.Role,
			})
		}
		authorized := r.Group("/api")

		authorized.Use(authMiddleware(loginData.Email))
		{
			authorized.GET("/data", handleData)
		}
	})

	r.POST("/addcustomer", authMiddleware("admin	"), func(c *gin.Context) {
		var customerData CustomerData
		if err := c.ShouldBindJSON(&customerData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "lỗi"})
			return
		}
		_, err := collection.InsertOne(context.TODO(), customerData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Thêm thành công"})
	})
	// hiển thị khách hàng
	// Truy vấn dữ liệu từ collection

	// http.HandleFunc("/users", GetUsers)
	// log.Fatal(http.ListenAndServe(":5000", nil));

	// func GetUsers(w http.ResponseWriter, r *http.Request) {
	// type User struct {
	// Name string
	// Email string
	// }

	// collection = client.Database("DB-test").Collection("test-collection")

	// cursor, err := collection.Find(context.TODO(), nil)
	// if err != nil {
	// log.Fatal(err)
	// }
	// defer cursor.Close(context.TODO())

	// var users []User
	// for cursor.Next(context.TODO()) {
	// var user User
	// err := cursor.Decode(&user)
	// if err != nil {
	// log.Fatal(err)
	// }
	// users = append(users, user)
	// }

	// w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(users)
	r.GET("/showcustomer", func(c *gin.Context) {
		query := c.DefaultQuery("q", "")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "5"))
		cursor, err := collection.Find(
			context.TODO(),
			bson.M{"fullname": primitive.Regex{Pattern: query, Options: "i"}},
			options.Find().SetSkip(int64((page-1)*pageSize)).SetLimit(int64(pageSize)),
		)
		total, _ := collection.CountDocuments(context.Background(), bson.M{"fullname": primitive.Regex{Pattern: query, Options: "i"}})

		k := (total / int64(pageSize))
		if total%int64(pageSize) != 0 {
			k++
		}
		if cursor == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Internal Server Error"})
			return
		}
		var people []Customer

		// Truy vấn dữ liệu từ MongoDB
		// cursor, err := collection.Find(context.TODO(), bson.M{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}
		// defer cursor.Close(context.TODO())

		// Lấy dữ liệu từ cursor và đưa vào slice people
		for cursor.Next(context.TODO()) {
			var customer Customer
			if err := cursor.Decode(&customer); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
				return
			}
			people = append(people, customer)
		}
		c.JSON(http.StatusOK, &Response{
			people,
			k,
		})
	})

	// search by fullname
	// r.GET("/search", func (c *gin.Context){
	// query:= c.DefaultQuery("q","")
	// cursor, err := collection.Find(context.TODO(), bson.M{"fullname": primitive.Regex{Pattern: query, Options: "i"}})
	// if err != nil {
	// c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	// return
	// }
	// var results []Customer
	// if err := cursor.All(context.TODO(), &results); err != nil {
	// c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	// return
	// }
	// c.JSON(http.StatusOK, results)
	// })
	fmt.Println("All run")

	r.Run(":5000")
}

type Customer struct {
	ID       string `bson:"_id"`
	Fullname string `bson:"fullname"`
	Email    string `bson:"email" `
	Phone    string `bson:"phone" `
	Address  string `bson:"address" `
	Id       int    `bson:"Id"`
}

type Response struct {
	People []Customer
	K      int64 `bson:"k"`
}
type CustomerData struct {
	Fullname string `bson:"fullname"`
	Email    string `bson:"email" `
	Phone    string `bson:"phone" `
	Password string `bson:"password"`
	Address  string `bson:"address" `
	Role     string `bson:"role" `
}
type Person struct {
	Fullname string `json:"fullname"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// type Cusomer struct {
// Fullname string `json:"fullname"`
// Email string `json:"email"`
// }
// func isValidUser(email, password string) bool {
// // Đây là nơi bạn thực hiện kiểm tra thông tin đăng nhập từ cơ sở dữ liệu
// // Trong ví dụ này, chỉ kiểm tra xem username và password có giống nhau không.
// return email == "users" && password == "pass"
// }

// Kiểm tra thông tin đăng nhập từ cơ sở dữ liệu
// Điều này thường liên quan đến truy vấn cơ sở dữ liệu để kiểm tra thông tin người dùng.

// Nếu thông tin đúng, trả về thành công
// if isValidUser(loginData.Email, loginData.Password) {
// c.JSON(http.StatusOK, gin.H{"message": "Đăng nhập thành côngs"})

// else {
// c.JSON(http.StatusUnauthorized, gin.H{"error": "Thông tin đăng nhập không chính xác"})
// }
// r.Run(":5000")
// }

// func isValidUser(email, password string) bool {

// // Đây là nơi bạn thực hiện kiểm tra thông tin đăng nhập từ cơ sở dữ liệu
// // Trong ví dụ này, chỉ kiểm tra xem username và password có giống nhau không.
// return email == "users" && password == "pass"

// }
