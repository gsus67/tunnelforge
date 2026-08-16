//go:build !windows

package main

func protegerSecretoSistema(plano []byte) ([]byte, error) {
	s, err := cifrar(string(plano))
	return []byte(s), err
}
func desprotegerSecretoSistema(protegido []byte) ([]byte, error) {
	s, err := descifrar(string(protegido))
	return []byte(s), err
}
