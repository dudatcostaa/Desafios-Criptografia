package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

/**
 * Classe responsável por ler uma chave assimétrica do disco.
 *
 * @see KeyFactory
 * @see KeySpec
 */

public class LeitorDeChaves {

    //https://www.baeldung.com/java-read-pem-file-keys
    /* Algoritmo:
    * 1 - Criar um arquivo (File)
    * 2 - Criar um leitor de arquivos (FileReader)
    * 3 - Criar um pemParser que vai ler e interpretar os arquivos que estão no formato pem
    * para chave privada retorna um PrivateKeyInfo
    * para chave pública retorna um SubjectPublicKeyInfo
    * 4 - Criar um JcaPEMKeyConverter que vai converter PrivateKeyInfo em PrivateKey
    *                                                   SubjectPublicKeyInfo em PublicKey
    * 5 - Realiza a leitura com readObject()
    * */

    /**
     * Lê a chave privada do local indicado.
     *
     * @param caminhoChave local do arquivo da chave privada.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave privada.
     */
    public static PrivateKey lerChavePrivadaDoDisco(String caminhoChave,
                                                    String algoritmo) {

        File arquivoChave = new File(caminhoChave); //1
        try (FileReader keyReader = new FileReader(arquivoChave)){ //2
            PEMParser pemParser = new PEMParser(keyReader); //3
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter(); //4
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject()); //5

            return converter.getPrivateKey(privateKeyInfo);

        } catch (IOException e){
            System.err.println("Erro ao ler chave privada");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Lê a chave pública do local indicado.
     *
     * @param caminhoChave local do arquivo da chave pública.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave pública.
     */
    public static PublicKey lerChavePublicaDoDisco(String caminhoChave,
                                                   String algoritmo) {

        File arquivoChave = new File(caminhoChave); //1
        try (FileReader keyReader = new FileReader(arquivoChave)){ //2
            PEMParser pemParser = new PEMParser(keyReader); //3
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter(); //4
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject()); //5

            return converter.getPublicKey(publicKeyInfo);

        } catch (Exception e) {
            System.err.println("Erro ao ler chave pública");
            e.printStackTrace();
            return null;
        }
    }
}