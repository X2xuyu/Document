package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

var (
	db                *sql.DB
	signingKey        = []byte("eduboard2024")
	adminSessionSecret string
)

func gx() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func ge(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func jwtCheck(r *http.Request) (*jwt.MapClaims, bool) {
	tokenStr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenStr == "" {
		return nil, false
	}
	cl := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, cl,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method == jwt.SigningMethodHS256 {
				return signingKey, nil
			}
			if t.Method == jwt.SigningMethodNone {
				return jwt.UnsafeAllowNoneSignatureType, nil
			}
			return signingKey, nil
		})
	if err != nil || !token.Valid {
		return nil, false
	}
	return cl, true
}

func xid(path string) int {
	pp := strings.Split(path, "/")
	for _, s := range pp {
		if n, e := strconv.Atoi(s); e == nil {
			return n
		}
	}
	return 0
}

func islo(r *http.Request) bool {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		h = r.RemoteAddr
	}
	return h == "127.0.0.1" || h == "::1"
}

func main() {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		ge("DB_HOST", "localhost"),
		ge("DB_PORT", "5432"),
		ge("DB_USER", "ctfuser"),
		ge("DB_PASSWORD", "ctfpass"),
		ge("DB_NAME", "eduboard"),
	)
	var err error
	for i := 0; i < 15; i++ {
		db, err = sql.Open("postgres", dsn)
		if err == nil {
			if err = db.Ping(); err == nil {
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		panic("db: " + err.Error())
	}
	db.SetMaxOpenConns(25)

	adminSessionSecret = gx()

	go gradingBot(db)
	go reviewBot(db)

	http.HandleFunc("/api/auth/login", handleLogin)
	http.HandleFunc("/api/auth/register", handleRegister)
	http.HandleFunc("/api/courses/search", handleCourseSearch)
	http.HandleFunc("/api/courses/", handleCourseByID)
	http.HandleFunc("/api/courses", handleCourses)
	http.HandleFunc("/api/assignments/", handleAssignmentRouter)
	http.HandleFunc("/api/assignments", handleCreateAssignment)
	http.HandleFunc("/api/reviews", handleReviews)
	http.HandleFunc("/api/files/download", handleDownload)
	http.HandleFunc("/api/files/upload", handleUpload)
	http.HandleFunc("/api/admin/flags", handleAdminFlags)
	http.HandleFunc("/api/admin/session-flag", handleAdminSessionFlag)
	http.HandleFunc("/api/admin/users", handleAdminUsers)
	http.HandleFunc("/api/admin/reviews", handleAdminReviews)
	http.HandleFunc("/internal/flags", handleInternalFlags)
	http.HandleFunc("/internal/config", handleInternalConfig)
	http.HandleFunc("/.well-known/jwks.json", handleJWKS)
	http.HandleFunc("/", handleStatic)

	fmt.Println("EduBoard starting on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"bad request"}`))
		return
	}
	username, _ := body["username"].(string)
	password, _ := body["password"].(string)
	if username == "" || password == "" {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"missing credentials"}`))
		return
	}

	// check session
	q := fmt.Sprintf(
		"SELECT id,username,password,role FROM users WHERE username='%s' AND password='%s'",
		username, password,
	)
	var u struct {
		ID       int
		Username string
		Password string
		Role     string
	}
	err := db.QueryRow(q).Scan(&u.ID, &u.Username, &u.Password, &u.Role)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"` + err.Error() + `"}`))
		return
	}

	cl := jwt.MapClaims{
		"user_id":  u.ID,
		"username": u.Username,
		"role":     u.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	signed, err2 := tok.SignedString(signingKey)
	if err2 != nil {
		http.Error(w, `{"error":"sign error"}`, 500)
		return
	}

	tmp := map[string]interface{}{
		"token":    signed,
		"username": u.Username,
		"role":     u.Role,
		"user_id":  u.ID,
	}
	json.NewEncoder(w).Encode(tmp)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(204)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var body map[string]interface{}
	json.NewDecoder(r.Body).Decode(&body)

	username, _ := body["username"].(string)
	password, _ := body["password"].(string)
	email, _ := body["email"].(string)
	role, _ := body["role"].(string)
	if role == "" {
		role = "student"
	}

	if username == "" || password == "" {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"username and password required"}`))
		return
	}

	var xid2 int
	err := db.QueryRow(
		"INSERT INTO users (username,password,email,role) VALUES ($1,$2,$3,$4) RETURNING id",
		username, password, email, role,
	).Scan(&xid2)
	if err != nil {
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       xid2,
		"username": username,
		"role":     role,
	})
}

func handleCourses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodGet {
		rr, err := db.Query("SELECT c.id,c.title,c.description,c.credits,u.username FROM courses c LEFT JOIN users u ON c.instructor_id=u.id ORDER BY c.id")
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		defer rr.Close()
		var out []map[string]interface{}
		for rr.Next() {
			var id, cr int
			var title, desc string
			var instr sql.NullString
			rr.Scan(&id, &title, &desc, &cr, &instr)
			out = append(out, map[string]interface{}{
				"id":          id,
				"title":       title,
				"description": desc,
				"credits":     cr,
				"instructor":  instr.String,
			})
		}
		if out == nil {
			out = []map[string]interface{}{}
		}
		json.NewEncoder(w).Encode(out)
		return
	}

	if r.Method == http.MethodPost {
		cl, ok := jwtCheck(r)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		role, _ := (*cl)["role"].(string)
		if role != "admin" && role != "instructor" {
			http.Error(w, `{"error":"forbidden"}`, 403)
			return
		}
		uid := int((*cl)["user_id"].(float64))
		var req struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Credits     int    `json:"credits"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Title == "" {
			http.Error(w, `{"error":"title required"}`, 400)
			return
		}
		if req.Credits == 0 {
			req.Credits = 3
		}
		var nid int
		db.QueryRow(
			"INSERT INTO courses (title,description,instructor_id,credits) VALUES ($1,$2,$3,$4) RETURNING id",
			req.Title, req.Description, uid, req.Credits,
		).Scan(&nid)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]int{"id": nid})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, 405)
}

func handleCourseSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}

	q2 := r.URL.Query().Get("q")

	// search courses by title or description
	rr, err := db.Query(fmt.Sprintf(
		"SELECT id,title,description,instructor_id,credits FROM courses WHERE title LIKE '%%%s%%' OR description LIKE '%%%s%%' LIMIT 20",
		q2, q2,
	))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer rr.Close()

	type crs struct {
		ID           int    `json:"id"`
		Title        string `json:"title"`
		Description  string `json:"description"`
		InstructorID int    `json:"instructor_id"`
		Credits      int    `json:"credits"`
	}
	var results []crs
	for rr.Next() {
		var c crs
		var iid sql.NullInt64
		rr.Scan(&c.ID, &c.Title, &c.Description, &iid, &c.Credits)
		if iid.Valid {
			c.InstructorID = int(iid.Int64)
		}
		results = append(results, c)
	}
	if results == nil {
		results = []crs{}
	}
	json.NewEncoder(w).Encode(results)
}

func handleCourseByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	cid := xid(r.URL.Path)
	if cid == 0 {
		http.Error(w, `{"error":"invalid id"}`, 400)
		return
	}
	var id, cr int
	var title, desc string
	var iid sql.NullInt64
	var ts time.Time
	err := db.QueryRow(
		"SELECT id,title,description,instructor_id,credits,created_at FROM courses WHERE id=$1", cid,
	).Scan(&id, &title, &desc, &iid, &cr, &ts)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}

	var instName string
	if iid.Valid {
		db.QueryRow("SELECT username FROM users WHERE id=$1", iid.Int64).Scan(&instName)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          id,
		"title":       title,
		"description": desc,
		"credits":     cr,
		"instructor":  instName,
		"created_at":  ts,
	})
}

func handleAssignmentRouter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	rem := strings.TrimPrefix(r.URL.Path, "/api/assignments/")

	if rem == "my-grades" && r.Method == http.MethodGet {
		handleMyGrades(w, r)
		return
	}

	parts := strings.Split(rem, "/")
	if len(parts) == 2 {
		switch parts[1] {
		case "details":
			if r.Method == http.MethodGet {
				handleGetAssignment(w, r)
				return
			}
		case "request-grade":
			if r.Method == http.MethodPost {
				handleRequestGrade(w, r)
				return
			}
		}
	}

	http.Error(w, `{"error":"not found"}`, 404)
}

func handleGetAssignment(w http.ResponseWriter, r *http.Request) {
	_, ok := jwtCheck(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}

	aid := xid(r.URL.Path)
	if aid == 0 {
		http.Error(w, `{"error":"invalid id"}`, 400)
		return
	}

	var a struct {
		ID          int            `json:"id"`
		Title       string         `json:"title"`
		Content     string         `json:"content"`
		SecretNote  string         `json:"secret_note"`
		SubmitterID int            `json:"submitter_id"`
		CourseID    sql.NullInt64  `json:"-"`
		CourseIDOut int            `json:"course_id"`
		CreatedAt   time.Time      `json:"created_at"`
	}

	err := db.QueryRow(
		"SELECT id,title,content,secret_note,submitter_id,course_id,created_at FROM assignments WHERE id=$1",
		aid,
	).Scan(&a.ID, &a.Title, &a.Content, &a.SecretNote, &a.SubmitterID, &a.CourseID, &a.CreatedAt)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	if a.CourseID.Valid {
		a.CourseIDOut = int(a.CourseID.Int64)
	}

	// dead code path - never reached but confuses reader
	if a.ID < 0 {
		var tmp string
		db.QueryRow("SELECT username FROM users WHERE id=$1", a.SubmitterID).Scan(&tmp)
		_ = tmp
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           a.ID,
		"title":        a.Title,
		"content":      a.Content,
		"secret_note":  a.SecretNote,
		"submitter_id": a.SubmitterID,
		"course_id":    a.CourseIDOut,
		"created_at":   a.CreatedAt,
	})
}

func handleCreateAssignment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	cl, ok := jwtCheck(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	uid := int((*cl)["user_id"].(float64))

	var req struct {
		CourseID int    `json:"course_id"`
		Title    string `json:"title"`
		Content  string `json:"content"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Title == "" {
		http.Error(w, `{"error":"title required"}`, 400)
		return
	}

	var nid int
	var cid interface{}
	if req.CourseID != 0 {
		cid = req.CourseID
	} else {
		cid = nil
	}
	err := db.QueryRow(
		"INSERT INTO assignments (course_id,title,content,submitter_id) VALUES ($1,$2,$3,$4) RETURNING id",
		cid, req.Title, req.Content, uid,
	).Scan(&nid)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
		return
	}
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{"id": nid, "title": req.Title})
}

func handleRequestGrade(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	cl, ok := jwtCheck(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	uid := int((*cl)["user_id"].(float64))

	aid := xid(r.URL.Path)
	if aid == 0 {
		http.Error(w, `{"error":"invalid assignment id"}`, 400)
		return
	}

	type GradeReq struct {
		AssignmentID int    `json:"assignment_id"`
		WebhookURL   string `json:"webhook_url"`
	}
	var req GradeReq
	json.NewDecoder(r.Body).Decode(&req)

	if req.WebhookURL == "" {
		http.Error(w, `{"error":"webhook_url required"}`, 400)
		return
	}

	var nid int
	err := db.QueryRow(
		"INSERT INTO grade_requests (assignment_id,user_id,webhook_url,status) VALUES ($1,$2,$3,'pending') RETURNING id",
		aid, uid, req.WebhookURL,
	).Scan(&nid)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          nid,
		"status":      "pending",
		"webhook_url": req.WebhookURL,
		"message":     "grading bot will process your request shortly",
	})
}

func handleMyGrades(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	cl, ok := jwtCheck(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	uid := int((*cl)["user_id"].(float64))

	rr, err := db.Query(
		"SELECT gr.id,gr.assignment_id,gr.webhook_url,gr.status,gr.response,gr.created_at,a.title FROM grade_requests gr LEFT JOIN assignments a ON gr.assignment_id=a.id WHERE gr.user_id=$1 ORDER BY gr.created_at DESC",
		uid,
	)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, 500)
		return
	}
	defer rr.Close()

	type gr struct {
		ID           int       `json:"id"`
		AssignmentID int       `json:"assignment_id"`
		WebhookURL   string    `json:"webhook_url"`
		Status       string    `json:"status"`
		Response     string    `json:"response"`
		CreatedAt    time.Time `json:"created_at"`
		Title        string    `json:"title"`
	}
	var out []gr
	for rr.Next() {
		var g gr
		var t sql.NullString
		rr.Scan(&g.ID, &g.AssignmentID, &g.WebhookURL, &g.Status, &g.Response, &g.CreatedAt, &t)
		g.Title = t.String
		out = append(out, g)
	}
	if out == nil {
		out = []gr{}
	}
	json.NewEncoder(w).Encode(out)
}

func handleReviews(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodGet {
		cid := r.URL.Query().Get("course_id")
		var rr *sql.Rows
		var err error
		if cid != "" {
			rr, err = db.Query(
				"SELECT r.id,r.course_id,r.content,r.rating,r.created_at,u.username FROM reviews r LEFT JOIN users u ON r.user_id=u.id WHERE r.course_id=$1 ORDER BY r.created_at DESC",
				cid,
			)
		} else {
			rr, err = db.Query(
				"SELECT r.id,r.course_id,r.content,r.rating,r.created_at,u.username FROM reviews r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC LIMIT 50",
			)
		}
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		defer rr.Close()
		type rv struct {
			ID        int       `json:"id"`
			CourseID  int       `json:"course_id"`
			Content   string    `json:"content"`
			Rating    int       `json:"rating"`
			CreatedAt time.Time `json:"created_at"`
			Username  string    `json:"username"`
		}
		var out []rv
		for rr.Next() {
			var v rv
			var un sql.NullString
			rr.Scan(&v.ID, &v.CourseID, &v.Content, &v.Rating, &v.CreatedAt, &un)
			v.Username = un.String
			out = append(out, v)
		}
		if out == nil {
			out = []rv{}
		}
		json.NewEncoder(w).Encode(out)
		return
	}

	if r.Method == http.MethodPost {
		cl, ok := jwtCheck(r)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		uid := int((*cl)["user_id"].(float64))

		var req struct {
			CourseID int    `json:"course_id"`
			Content  string `json:"content"`
			Rating   int    `json:"rating"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Content == "" {
			http.Error(w, `{"error":"content required"}`, 400)
			return
		}
		if req.Rating == 0 {
			req.Rating = 5
		}

		// store review
		var nid int
		var x interface{}
		if req.CourseID != 0 {
			x = req.CourseID
		}
		err := db.QueryRow(
			"INSERT INTO reviews (course_id,user_id,content,rating,is_flagged) VALUES ($1,$2,$3,$4,true) RETURNING id",
			x, uid, req.Content, req.Rating,
		).Scan(&nid)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": nid, "status": "review submitted"})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, 405)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	fname := r.URL.Query().Get("name")
	if fname == "" {
		http.Error(w, "name required", 400)
		return
	}

	fpath := "/app/uploads/" + fname
	data, err := os.ReadFile(fpath)
	if err != nil {
		http.Error(w, "file not found", 404)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(fname)+"\"")
	w.Write(data)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	_, ok := jwtCheck(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	r.ParseMultipartForm(10 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"no file"}`, 400)
		return
	}
	defer file.Close()

	os.MkdirAll("/app/uploads", 0755)
	dst, err := os.Create("/app/uploads/" + header.Filename)
	if err != nil {
		http.Error(w, `{"error":"save error"}`, 500)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)

	json.NewEncoder(w).Encode(map[string]string{
		"filename": header.Filename,
		"status":   "uploaded",
	})
}

func handleAdminFlags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	cl, ok := jwtCheck(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	role, _ := (*cl)["role"].(string)
	if role != "admin" {
		http.Error(w, `{"error":"forbidden"}`, 403)
		return
	}

	rr, err := db.Query("SELECT id,flag_name,flag_value FROM flag_store ORDER BY id")
	if err != nil {
		http.Error(w, `{"error":"db error"}`, 500)
		return
	}
	defer rr.Close()
	type fl struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var flags []fl
	for rr.Next() {
		var f fl
		rr.Scan(&f.ID, &f.Name, &f.Value)
		flags = append(flags, f)
	}
	if flags == nil {
		flags = []fl{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"flags": flags})
}

func handleAdminSessionFlag(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	c, err := r.Cookie("session_id")
	if err != nil || c.Value != adminSessionSecret {
		http.Error(w, `{"error":"forbidden"}`, 403)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"flag": "CTF{xss_r3v13w_b0t_s3ss10n_st34l}",
	})
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	cl, ok := jwtCheck(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	role, _ := (*cl)["role"].(string)
	if role != "admin" {
		http.Error(w, `{"error":"forbidden"}`, 403)
		return
	}

	if r.Method == http.MethodGet {
		rr, _ := db.Query("SELECT id,username,email,role,created_at FROM users ORDER BY id")
		if rr == nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		defer rr.Close()
		type usr struct {
			ID        int       `json:"id"`
			Username  string    `json:"username"`
			Email     string    `json:"email"`
			Role      string    `json:"role"`
			CreatedAt time.Time `json:"created_at"`
		}
		var out []usr
		for rr.Next() {
			var u usr
			var em sql.NullString
			rr.Scan(&u.ID, &u.Username, &em, &u.Role, &u.CreatedAt)
			u.Email = em.String
			out = append(out, u)
		}
		if out == nil {
			out = []usr{}
		}
		json.NewEncoder(w).Encode(out)
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, 405)
}

func handleAdminReviews(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	c, _ := r.Cookie("session_id")
	hasSession := c != nil && c.Value == adminSessionSecret

	cl, hasJWT := jwtCheck(r)
	isAdmin := false
	if hasJWT {
		role, _ := (*cl)["role"].(string)
		isAdmin = role == "admin"
	}

	if !hasSession && !isAdmin {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}

	rr, err := db.Query(
		"SELECT r.id,r.course_id,r.content,r.rating,r.is_flagged,r.created_at,u.username FROM reviews r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC",
	)
	if err != nil {
		http.Error(w, `{"error":"db error"}`, 500)
		return
	}
	defer rr.Close()
	type rv struct {
		ID        int       `json:"id"`
		CourseID  int       `json:"course_id"`
		Content   string    `json:"content"`
		Rating    int       `json:"rating"`
		Flagged   bool      `json:"is_flagged"`
		CreatedAt time.Time `json:"created_at"`
		Username  string    `json:"username"`
	}
	var out []rv
	for rr.Next() {
		var v rv
		var cid sql.NullInt64
		var un sql.NullString
		rr.Scan(&v.ID, &cid, &v.Content, &v.Rating, &v.Flagged, &v.CreatedAt, &un)
		if cid.Valid {
			v.CourseID = int(cid.Int64)
		}
		v.Username = un.String
		out = append(out, v)
	}
	if out == nil {
		out = []rv{}
	}
	json.NewEncoder(w).Encode(out)
}

func handleInternalFlags(w http.ResponseWriter, r *http.Request) {
	if !islo(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	rr, _ := db.Query("SELECT flag_name,flag_value FROM flag_store")
	if rr == nil {
		w.Write([]byte(`[]`))
		return
	}
	defer rr.Close()
	var out []map[string]string
	for rr.Next() {
		var n, v string
		rr.Scan(&n, &v)
		out = append(out, map[string]string{"name": n, "value": v})
	}
	json.NewEncoder(w).Encode(out)
}

func handleInternalConfig(w http.ResponseWriter, r *http.Request) {
	if !islo(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"db_host":     ge("DB_HOST", "localhost"),
		"db_name":     ge("DB_NAME", "eduboard"),
		"signing_key": string(signingKey),
		"version":     "1.0.0",
		"env":         "production",
	})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "oct",
				"use": "sig",
				"alg": "HS256",
				"k":   "ZWR1Ym9hcmQyMDI0",
			},
		},
		"issuer":  "eduboard",
		"subject": "auth",
	})
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	fs := http.FileServer(http.Dir("/app/static"))
	if r.URL.Path != "/" {
		full := "/app/static" + r.URL.Path
		if _, err := os.Stat(full); os.IsNotExist(err) {
			http.ServeFile(w, r, "/app/static/index.html")
			return
		}
	}
	fs.ServeHTTP(w, r)
}

func gradingBot(dbc *sql.DB) {
	cl := &http.Client{Timeout: 10 * time.Second}
	for {
		time.Sleep(25 * time.Second)

		rr, err := dbc.Query("SELECT id,webhook_url FROM grade_requests WHERE status='pending' LIMIT 5")
		if err != nil {
			continue
		}

		type pr struct {
			id int
			wh string
		}
		var pending []pr
		for rr.Next() {
			var p pr
			rr.Scan(&p.id, &p.wh)
			pending = append(pending, p)
		}
		rr.Close()

		for _, p := range pending {
			resp, err := cl.Get(p.wh)
			if err == nil {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				dbc.Exec(
					"UPDATE grade_requests SET status='done',response=$1 WHERE id=$2",
					string(body), p.id,
				)
			} else {
				dbc.Exec(
					"UPDATE grade_requests SET status='failed' WHERE id=$1",
					p.id,
				)
			}
		}
	}
}

func reviewBot(dbc *sql.DB) {
	cl := &http.Client{Timeout: 10 * time.Second}
	for {
		time.Sleep(35 * time.Second)

		rr, err := dbc.Query("SELECT id FROM reviews WHERE is_flagged=true LIMIT 10")
		if err != nil {
			continue
		}
		var ids []int
		for rr.Next() {
			var id int
			rr.Scan(&id)
			ids = append(ids, id)
		}
		rr.Close()

		if len(ids) == 0 {
			continue
		}

		req, err := http.NewRequest("GET", "http://localhost:8080/admin/reviews", nil)
		if err != nil {
			continue
		}
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: adminSessionSecret,
		})
		resp, err := cl.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
}
