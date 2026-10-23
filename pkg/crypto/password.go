package crypto

import (
	"golang.org/x/crypto/bcrypt"
)

// DefaultCost bcrypt 默认计算成本 (等保推荐 >= 10)
const DefaultCost = 12

// HashPassword 对密码进行加盐哈希
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash 验证明文密码与哈希值
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
