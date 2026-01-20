package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import br.ufsc.labsec.pbad.hiring.Constantes;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Essa classe representa um repositório de chaves do tipo PKCS#12.
 *
 * @see KeyStore
 */
public class
RepositorioChaves {

    private KeyStore repositorio;
    private char[] senha;
    private String alias;

    /**
     * Construtor.
     * Inicializar os atributos com as Constantes definidas em Constantes
     */
    public RepositorioChaves() {
        try {
            this.repositorio = KeyStore.getInstance(Constantes.formatoRepositorio);
            this.senha = Constantes.senhaMestre;
            this.alias = Constantes.aliasUsuario;
        } catch (KeyStoreException e){
            e.printStackTrace();
        }
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     * abrir com load, exc de load
     */
    public void abrir(String caminhoRepositorio) {
        try {
            this.repositorio.load(new FileInputStream(caminhoRepositorio), senha);
        } catch (NoSuchAlgorithmException | SecurityException | IOException | CertificateException e){
            e.printStackTrace();
        }
    }

    /**
     * Obtém a chave privada do PKCS#12.
     *
     * @return Chave privada.
     * retornar com getKey
     */
    public PrivateKey pegarChavePrivada() {
        try {
            return (PrivateKey) this.repositorio.getKey(this.alias, this.senha);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Obtém do certificado do PKCS#12.
     *
     * @return Certificado.
     * retornar com getCertificate
     */
    public X509Certificate pegarCertificado() {
        try {
            return (X509Certificate) this.repositorio.getCertificate(this.alias);
        } catch (KeyStoreException e){
            e.printStackTrace();
            return null;
        }
    }

}
