package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.security.*;

/**
 * Classe responsável por gerar pares de chaves assimétricas.
 *
 * @see KeyPair
 * @see PublicKey
 * @see PrivateKey
 */
public class GeradorDeChaves {
    //https://www.mayrhofer.eu.org/post/create-x509-certs-in-java/

    private String algoritmo;
    private KeyPairGenerator generator;
    private SecureRandom secureRandom;

    /**
     * Construtor.
     * Algoritmo:
     * 1 - inicializar os atributos da classe
     * 2 - inicializa o par de chaves
     * 3 - gerar sequência aleatória segura com SecureRandom
     *
     * @param algoritmo algoritmo de criptografia assimétrica a ser usado.
     */

    public GeradorDeChaves(String algoritmo) throws NoSuchAlgorithmException {
        this.algoritmo = algoritmo;
        this.generator = KeyPairGenerator.getInstance(this.algoritmo); //https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html
        this.secureRandom = new SecureRandom();
    }

    /**
     * Gera um par de chaves, usando o algoritmo definido pela classe, com o
     * tamanho da chave especificado.
     *
     * @param tamanhoDaChave tamanho em bits das chaves geradas.
     * @return Par de chaves.
     * @see SecureRandom //usei no construtor, gera uma sequência criptograficamente segura https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html
     */

    public KeyPair gerarParDeChaves(int tamanhoDaChave) {
            generator.initialize(tamanhoDaChave, this.secureRandom);
            return generator.generateKeyPair();
    }

}
