package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import java.io.*;
import java.security.Key;
import java.security.PrivateKey;

/**
 * Essa classe é responsável por escrever uma chave assimétrica no disco. Note
 * que a chave pode ser tanto uma chave pública quanto uma chave privada.
 *
 * @see Key
 */

public class EscritorDeChaves {

    /**
     * Escreve uma chave no local indicado.
     *
     * @param chave         chave assimétrica a ser escrita em disco.
     * @param nomeDoArquivo nome do local onde será escrita a chave.
     *
     * Algoritmo:
     * 1 - criar um Writer, criar um JCAPEMWriter e passar o writer para ele
     * 2 - checar se é privada ou pública
     * 3 - chaves privadas não podem ser salvas como qualquer objeto, precisam estar codificadas
     * então criamos um objeto JcaPKCS8Generator que converte a minha chave privada para o formato correto
     * 4 - coloca em formato pem
     */

    //https://stackoverflow.com/questions/24506246/java-how-to-save-a-private-key-in-a-pem-file-with-password-protection
    public static void escreveChaveEmDisco(Key chave, String nomeDoArquivo) {
        try (Writer writer = new FileWriter(nomeDoArquivo); //1
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) { //https://downloads.bouncycastle.org/java/docs/bcpkix-jdk14-javadoc/org/bouncycastle/openssl/jcajce/JcaPEMWriter.html escreve o arquivo em formato pem

            if (chave instanceof PrivateKey) { //2
                JcaPKCS8Generator generator = new JcaPKCS8Generator((PrivateKey) chave, null); //3 https://downloads.bouncycastle.org/java/docs/bcpkix-jdk18on-javadoc/org/bouncycastle/openssl/jcajce/JcaPKCS8Generator.html
                PemObject chavePKCS8 = generator.generate(); //4 https://downloads.bouncycastle.org/java/docs/bcprov-jdk15to18-javadoc/org/bouncycastle/util/io/pem/PemObject.html
                pemWriter.writeObject(chavePKCS8);
            } else {
                pemWriter.writeObject(chave);
            }

        } catch (IOException e) {
            System.err.println("Erro ao escrever chave");
            e.printStackTrace();
        }
    }


}
