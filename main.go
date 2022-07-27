package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/smtp"
	"regexp"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

const (
	Sender   = "taoziyouzi@gmail.com"
	PassWord = "zz319013656"
	host     = "smtp.gmail.com"
	port     = 587
)
const (
	USERNAME = "root"
	PASSWORD = "123"
	NETWORK  = "tcp"
	SERVER   = "127.0.0.1"
	PORT     = 3306
	DATABASE = "dong"
)

const (
	InvalidInputErrorCode      = 1000
	UsernameNotExistCode       = 1001
	IncorrectPasswordErrorCode = 1002
	NormalErrorCode            = 1003
	UserNotLoggedInCode        = 1004
	NetWorkErrorCode           = 1005
	ConnectionRefusedCode      = 1006
	UnknownErrorCode           = 1007
)
const (
	MailboxAvailable            = "mailbox available"
	SendSuccessfully            = "send successfully"
	UserNameAvailable           = "user name available"
	UserNameRegistered          = "username registered"
	VerificationSuccessful      = "verification succession"
	SuccessfulRegistration      = "successful registration"
	LoginSuccessfully           = "log in successfully"
	PasswordUpdatedSuccessfully = "password updated successfully"
	LogoutSuccessful            = "log out successfully"
)

type ResponseMessage struct {
	Message string `json:"message"`
}
type ResponseError struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}
type User struct {
	Username string
	Password string
}
type UpdatePsd struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}
type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Code     int    `json:"code"`
}
type TestUserInfo struct {
	NickName    string `json:"nickname"`
	PhoneNumber string `json:"phoneNumber"`
	Email       string `json:"email"`
}
type DatabaseInfo struct {
	UserName string
}
type Token struct {
	Token string
	Email string
	Code  int
	Time  int64
}
type EmailAndCode struct {
	Email string `json:"email"`
	Code  int
}
type Email struct {
	Username    string
	Email       string
	Code        int
	NewPassword string
}

func RespondInternalServerError(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	responseError := ResponseError{
		Code:  code,
		Error: err.Error(),
	}
	data, err := json.Marshal(responseError)
	if err != nil {
		fmt.Println("respond json.marshal failed", err)
		return
	}
	_, err = w.Write(data)
	if err != nil {
		fmt.Println("respond write data failed", err)
		return
	}
}
func RespondRequest(w http.ResponseWriter, message string) {
	responseMessage := ResponseMessage{
		Message: message,
	}
	data, err := json.Marshal(responseMessage)
	if err != nil {
		fmt.Println("respond json.marshal failed")
	}
	_, err = w.Write(data)
	if err != nil {
		fmt.Println("respond write data failed", err)
		return
	}
}
func RespondBadRequestError(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(http.StatusBadRequest)
	responseError := ResponseError{
		Code:  code,
		Error: err.Error(),
	}
	data, err := json.Marshal(responseError)
	if err != nil {
		fmt.Println("request json.marshal failed", err)
		return
	}
	_, err = w.Write(data)
	if err != nil {
		fmt.Println("request write failed", err)
		return
	}
}
func newDB() (*sql.DB, error) {
	conn := fmt.Sprintf("%s:%s@%s(%s:%d)/%s", USERNAME, PASSWORD, NETWORK, SERVER, PORT, DATABASE)
	DB, err := sql.Open("mysql", conn)
	if err != nil {
		fmt.Println("connection to mysql failed:", err)
		return nil, err
	}
	return DB, err
}
func RandomNumber() string {
	return fmt.Sprintf("%06v", rand.New(rand.NewSource(time.Now().UnixNano())).Int31n(1000000))
}

//func QueryAllData(DB *sql.DB,username string)  (string,string,string,error){
//	user :=new(TestUserInfo)
//	row :=DB.QueryRow("select nickname,phonenumber,email from user where name=?",username)
//	err :=row.Scan(&user.NickName,&user.PhoneNumber,&user.Email)
//	if err!=nil{
//		if err==sql.ErrNoRows {
//			fmt.Println("no data")
//		}else{
//			fmt.Printf("scan failed, err:%v\n", err)
//			return "","","",err
//		}
//	}
//	return user.NickName,user.PhoneNumber,user.Email,nil
//}
func Query(DB *sql.DB, username string) (string, error) {
	user := new(User)
	row := DB.QueryRow("select password  from user where name=?", username)
	err := row.Scan(&user.Password)
	if err != nil {
		fmt.Printf("scan failed, err:%v\n", err)
		return "", err
	}
	return user.Password, err
}
func QueryEmail(DB *sql.DB, email string) error {
	Email := new(Token)
	row := DB.QueryRow("select email from user where email=?", email)
	err := row.Scan(&Email.Email)
	if err != nil {
		fmt.Println("scan failed", err)
		return err
	}
	return err
}
func QueryEmailInCode(DB *sql.DB, email string) error {
	Email := new(Email)
	row := DB.QueryRow("select email from code where email=?", email)
	err := row.Scan(&Email.Email)
	if err != nil {
		fmt.Println("scan failed", err)
		return err
	}
	return err
}
func QueryCodeTimeInCode(DB *sql.DB, email string) (int, int64, error) {
	code := new(Token)
	row := DB.QueryRow("select code,time from code where email=?", email)
	err := row.Scan(&code.Code, &code.Time)
	if err != nil {
		fmt.Println("scan failed", err)
		return 0, 0, err
	}
	return code.Code, code.Time, err
}
func QueryToken(DB *sql.DB, username string) (string, error) {
	token := new(Token)
	row := DB.QueryRow("select token from user where name=?", username)
	err := row.Scan(&token.Token)
	if err != nil {
		fmt.Println("user not logged in", err)
		return "", err
	}
	return token.Token, err

}
func InsertEmail(DB *sql.DB, email string) error {
	_, err := DB.Exec("insert into code (email) values (?)", email)
	if err != nil {
		fmt.Println("insert email failed", err)
		return err
	}
	return err
}
func InsertUserInfo(DB *sql.DB, password string, username string, email string) error {
	_, err := DB.Exec("insert into user (password,name,email) values (?,?,?)", password, username, email)
	if err != nil {
		fmt.Println("insert failed", err)
		return err
	}
	return nil
}
func InsertRegisterTime(DB *sql.DB, Time int64, email string) error {
	_, err := DB.Exec("update code set registrationTime=? where email=?", Time, email)
	if err != nil {
		fmt.Println("insert data failed", err)
		return err
	}
	return nil
}
func Delete(DB *sql.DB, Time int64) error {
	_, err := DB.Exec("delete from code where time=?", Time)
	if err != nil {
		fmt.Println("delete data failed", err)
		return err
	}
	return nil
}
func RegisterQueryUserName(DB *sql.DB, username string) (string, error) {
	DatabaseUsername := new(DatabaseInfo)
	row := DB.QueryRow("select name from user where name =?", username)
	err := row.Scan(&DatabaseUsername.UserName)
	if err != nil {
		fmt.Println("scan failed", err)
		return "", err
	}
	return DatabaseUsername.UserName, err
}
func VerifyEmailFormat(email string) bool {
	pattern := `^[0-9a-z][_.0-9a-z-]{0,31}@([0-9a-z][0-9a-z-]{0,30}[0-9a-z]\.){1,4}[a-z]{2,4}$`
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}
func SendEmail(email string) (int, error) {

	Auth := smtp.PlainAuth("", Sender, PassWord, host)
	receivers := []string{email}
	rand.Seed(time.Now().Unix())
	Code := rand.Intn(10000)
	str := fmt.Sprintf("From:taoziyouzi@gmail.com\r\nTo:taoziyouzio@163.com\r\nSubject:verifycode\r\n\r\n%d\r\n", Code)
	msg := []byte(str)
	err := smtp.SendMail(host+":"+strconv.Itoa(port),
		Auth,
		Sender,
		receivers,
		msg,
	)
	if err != nil {
		fmt.Println("send failed", err)
		return 0, err
	}
	return Code, err
}
func UpdateEmailInCode(DB *sql.DB, email string) error {
	_, err := DB.Exec("update code set email=? where email=?", email)
	if err != nil {
		fmt.Println("update email failed", err)
		return err
	}
	return err
}
func UpdateCodeAndTime(DB *sql.DB, code int, Time int64, email string) error {
	_, err := DB.Exec("update code set code=? ,time=? where email=?", code, Time, email)
	if err != nil {
		fmt.Println("update code time failed", err)
		return err
	}
	return err
}
func UpdateToken(DB *sql.DB, token string, username string) error {
	_, err := DB.Exec("update user set token=? where name=?", token, username)
	if err != nil {
		fmt.Println("update token failed", err)
		return err
	}
	return err
}
func ForgetUpdatePassword(DB *sql.DB, email string, newPassword string) error {
	_, err := DB.Exec("update user set password=? where email=?", newPassword, email)
	if err != nil {
		fmt.Println("update password failed", err)
		return err
	}
	return nil
}
func Update(DB *sql.DB, username string, password string) error {

	_, err := DB.Exec("update user set password=? where name=?", password, username)
	if err != nil {
		fmt.Println("update password failed", err)
		return err
	}
	return err
}
func SendCode(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("read data failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	User := &EmailAndCode{}
	err = json.Unmarshal(data, &User)
	if err != nil {
		fmt.Println("json.unmarshal failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	email := User.Email
	if email == "" {
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("mailbox cannot be empty"))
		return
	}
	if VerifyEmailFormat(email) {
		fmt.Println("mailbox legal")
	} else {
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("mailboxes format error"))
		return
	}
	fmt.Println("email:", email)
	db, err := newDB()
	if err != nil {
		fmt.Println("failed", err)
		RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
		return
	}
	err = QueryEmail(db, email)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("email can be used")
			//RespondRequest(w,MailboxAvailable)
		} else {
			fmt.Println("connection refused", err)
			RespondInternalServerError(w, NetWorkErrorCode, errors.New("connection refused"))
			return
		}
	} else {
		fmt.Println("mailbox registered")
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("mailbox registered"))
		return
	}
	err = QueryEmailInCode(db, email)
	if err != nil {
		if err == sql.ErrNoRows {
			err = InsertEmail(db, email)
			if err != nil {
				fmt.Println("insert email failed", err)
				RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
				return
			} else {
				fmt.Println("query email failed", err)
				RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
				return
			}
		} else {
			err = UpdateEmailInCode(db, email)
			if err != nil {
				fmt.Println("update email failed", err)
				RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
				return
			}
		}
	}

	code, err := SendEmail(email)
	if err != nil {
		fmt.Println("send email failed", err)
		RespondInternalServerError(w, NetWorkErrorCode, errors.New("connection refused"))
		return
	}
	now := time.Now()
	Time := now.Unix()
	err = UpdateCodeAndTime(db, code, Time, email)
	if err != nil {
		fmt.Println("connection refused", err)
		RespondInternalServerError(w, NetWorkErrorCode, errors.New("network error"))
		return
	}
	fmt.Println("code :", code)
	RespondRequest(w, SendSuccessfully)
}
func ClearToken(DB *sql.DB, Token string) error {
	_, err := DB.Exec("update user set token=null where token=?", Token)
	if err != nil {
		fmt.Println("clear token failed", err)
		return err
	}
	return nil
}
func RegisterHandle(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Read Body Failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	res := &UserInfo{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		fmt.Println("read data failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	username := res.Username
	if username == "" {
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("username can not empty"))
		fmt.Println("username can not empty")
		return
	}
	Password := res.Password
	if Password == "" {
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("password can not empty"))
		fmt.Println("password can not empty")
		return
	}
	email := res.Email
	if email == "" {
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("mailboxes can not empty"))
		fmt.Println("mailboxes can not empty")
		return
	}
	code := res.Code
	now := time.Now()
	Time := now.Unix()
	fmt.Println("username:", username)
	fmt.Println("password:", Password)
	fmt.Println("code:", code)
	db, err := newDB()
	if err != nil {
		RespondInternalServerError(w, NetWorkErrorCode, errors.New("connection refused"))
		fmt.Println("connection refused ", err)
		return
	}
	_, err = RegisterQueryUserName(db, username)
	if err != nil {
		if err == sql.ErrNoRows {
		} else {
			fmt.Println("query failed", err)
			RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
			return
		}
	} else {
		RespondRequest(w, UserNameRegistered)
		fmt.Println("username registered")
		return
	}
	err = QueryEmailInCode(db, email)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("mailbox  error ", err)
			RespondBadRequestError(w, InvalidInputErrorCode, errors.New("mailbox error"))
			return
		} else {
			fmt.Println("query email failed", err)
			RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
			return
		}
	}
	QueryCode, QueryTime, err := QueryCodeTimeInCode(db, email)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("code does not exist", err)
			RespondInternalServerError(w, UnknownErrorCode, errors.New("registration failed"))
			return
		} else {
			fmt.Println("query code failed", err)
			RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
			return
		}
	}
	if code == QueryCode {
		if Time-QueryTime > 60 {
			fmt.Println("verification code expiration")
			RespondBadRequestError(w, InvalidInputErrorCode, errors.New("verification code expiration"))
			return
		} else {
			fmt.Println("verification successful")
			RespondRequest(w, VerificationSuccessful)
		}
	} else {
		fmt.Println("incorrect verification code ")
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("incorrect verification code"))
		return
	}

	DATA := []byte(Password) //   加密
	has := md5.Sum(DATA)
	password := fmt.Sprintf("%x", has)

	err = InsertRegisterTime(db, Time, email)
	if err != nil {
		fmt.Println("insert data failed", err)
		RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
		return
	}
	err = InsertUserInfo(db, password, username, email)
	if err != nil {
		fmt.Println("update user info failed", err)
		RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
		return
	} else {
		fmt.Println("successful registration")
		RespondRequest(w, SuccessfulRegistration)
	}

}
func LoginHandle(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Read Body Failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	res := &UserInfo{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		fmt.Println("Unmarshal Failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}

	username := res.Username
	DATA := []byte(res.Password)
	has := md5.Sum(DATA)
	password := fmt.Sprintf("%x", has)
	fmt.Println("username:", username)
	fmt.Println("password:", password)
	db, err := newDB()
	if err != nil {
		fmt.Println("connection refused")
		RespondInternalServerError(w, NetWorkErrorCode, errors.New("network error"))
		return
	}

	RealUsername, err := RegisterQueryUserName(db, username)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("user does not exist", err)
			RespondBadRequestError(w, InvalidInputErrorCode, errors.New("user does not exist"))
			return
		} else {
			fmt.Println("connection refused")
			RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
			return
		}
	}
	RealPassword, err := Query(db, username)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("no password queried", err)
			RespondBadRequestError(w, IncorrectPasswordErrorCode, errors.New("password error"))
			return
		} else {
			fmt.Println("network error", err)
			RespondInternalServerError(w, NormalErrorCode, errors.New("network error"))
			return
		}
	}
	if RealPassword == password && RealUsername == username {
		fmt.Println("login success !")
		number := RandomNumber()
		fmt.Println("token:", number)
		cookie := http.Cookie{
			Name:     "token",
			Value:    number,
			HttpOnly: true,
		}
		token := cookie.Value
		http.SetCookie(w, &cookie)
		fmt.Println("token:", token)
		err = UpdateToken(db, token, username)
		if err != nil {
			fmt.Println("update token failed", err)
			RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
			return
		}
	}
	RespondRequest(w, LoginSuccessfully)
}
func UpdatePassword(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		RespondBadRequestError(w, UserNotLoggedInCode, errors.New("user not logged in"))
		fmt.Println("user not logged in", err)
		return
	}
	UserToken := cookie.Value
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("read data failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	} else {
		User := &UpdatePsd{}
		err = json.Unmarshal(data, &User)
		if err != nil {
			fmt.Println("json.unmarshal failed", err)
			RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
			return
		}
		db, err := newDB()
		username := User.UserName
		password := User.Password
		token, err := QueryToken(db, username)
		fmt.Println("token :", token)
		if token != UserToken {
			fmt.Println("the token is different")
			RespondBadRequestError(w, NormalErrorCode, errors.New("user not logged in"))
			if err != nil {
				fmt.Println("write data failed", err)
				return
			}
			return
		}
		err = Update(db, username, password)
		if err != nil {
			fmt.Println("update password failed", err)
			RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
			if err != nil {
				fmt.Println("write failed", err)
				return
			}
			return
		} else {
			fmt.Println("update password success")
			RespondRequest(w, PasswordUpdatedSuccessfully)
		}
	}
}
func ForgetPassword(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("invalid input", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	Code := &Email{}
	err = json.Unmarshal(data, &Code)
	if err != nil {
		fmt.Println("json.Unmarshal data failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}

	email := Code.Email
	if VerifyEmailFormat(email) {
	} else {
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("mailboxes format error"))
		return
	}
	db, err := newDB()
	err = QueryEmail(db, email)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("mailbox does not exit", err)
			RespondBadRequestError(w, InvalidInputErrorCode, errors.New("mailbox does not exist"))
			return
		} else {
			fmt.Println("connection refused", err)
			RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
			return
		}
	}
	code, err := SendEmail(email)
	if err != nil {
		fmt.Println("failed to send", err)
		RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
		return
	}
	fmt.Println("code:", code)
	now := time.Now()
	Time := now.Unix()
	err = UpdateCodeAndTime(db, code, Time, email)
	if err != nil {
		fmt.Println("update data failed", err)
		return
	}
	RespondRequest(w, SendSuccessfully)
}

func VerifyMailbox(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("read data failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	Code := &Email{}
	err = json.Unmarshal(data, &Code)
	if err != nil {
		fmt.Println("json.unmarshal data failed", err)
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("invalid input"))
		return
	}
	db, err := newDB()
	code := Code.Code
	email := Code.Email
	newPassword := Code.NewPassword
	now := time.Now()
	Time := now.Unix()
	QueryCode, QueryTime, err := QueryCodeTimeInCode(db, email)
	if err != nil {
		fmt.Println("query failed", err)
		RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
		return
	}

	if code == QueryCode {
		if Time-QueryTime > 60 {
			fmt.Println("verification code expiration")
			RespondBadRequestError(w, InvalidInputErrorCode, errors.New("verification code expiration"))
			return
		} else {
			fmt.Println("verification successful")
			RespondRequest(w, VerificationSuccessful)
		}
	} else {
		fmt.Println("incorrect verification code ")
		RespondBadRequestError(w, InvalidInputErrorCode, errors.New("incorrect verification code"))
		return
	}
	err = ForgetUpdatePassword(db, email, newPassword)
	if err != nil {
		fmt.Println("update password failed", err)
		RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
		return
	}
	fmt.Println("update password success")
	RespondRequest(w, PasswordUpdatedSuccessfully)

}
func LoginOut(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		fmt.Println("user not logged in", err)
		return
	}
	db, err := newDB()
	if err != nil {
		RespondInternalServerError(w, NetWorkErrorCode, errors.New("connection refused"))
		fmt.Println("connection refused")
		return
	}
	Token := cookie.Value
	err = ClearToken(db, Token)
	if err != nil {
		fmt.Println("clear failed", err)
		RespondInternalServerError(w, ConnectionRefusedCode, errors.New("connection refused"))
		return
	}
	fmt.Println("clear success")
	RespondRequest(w, LogoutSuccessful)
}

func main() {
	http.HandleFunc("/code", SendCode)
	http.HandleFunc("/register", RegisterHandle)
	http.HandleFunc("/login", LoginHandle)
	http.HandleFunc("/update", UpdatePassword)
	http.HandleFunc("/forget", ForgetPassword)
	http.HandleFunc("/verify", VerifyMailbox)
	http.HandleFunc("/out", LoginOut)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("ListenAndServe failed !", err)
		return
	}
	fmt.Println("hello world")
}
