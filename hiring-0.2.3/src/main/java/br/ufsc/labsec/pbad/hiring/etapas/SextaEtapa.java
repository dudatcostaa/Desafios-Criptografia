package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.VerificadorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;

/**
 * <b>Sexta etapa - verificar uma assinatura digital</b>
 * <p>
 * Por último, será necessário verificar a integridade da assinatura
 * recém gerada. Note que o processo de validação de uma assinatura
 * digital pode ser muito complexo, mas aqui o desafio será simples. Para
 * verificar a assinatura será necessário apenas decifrar o valor da
 * assinatura (resultante do processo de cifra do resumo criptográfico do
 * arquivo {@code textoPlano.txt} com as informações da estrutura da
 * assinatura) e comparar esse valor com o valor do resumo criptográfico do
 * arquivo assinado. Como dito na fundamentação, para assinar é usada a chave
 * privada, e para decifrar (verificar) é usada a chave pública.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * verificar a assinatura gerada na etapa anterior, de acordo com o
 * processo descrito, e apresentar esse resultado.
 * </li>
 * </ul>
 */
public class SextaEtapa {

    public static void executarEtapa() {
        try {
            RepositorioChaves repositorioChaves = new RepositorioChaves();
            repositorioChaves.abrir(Constantes.caminhoPkcs12Usuario);

            X509Certificate x509Certificate = repositorioChaves.pegarCertificado();

            VerificadorDeAssinatura verificadorDeAssinatura = new VerificadorDeAssinatura();

            try (FileInputStream fileInputStream = new FileInputStream(Constantes.caminhoAssinatura)){
                CMSSignedData cmsSignedData = new CMSSignedData(fileInputStream);
                boolean resultado = verificadorDeAssinatura.verificarAssinatura(x509Certificate, cmsSignedData);
                System.out.println(resultado);
            }
            System.out.println("Etapa 6 check");
        } catch (Exception e){
            e.printStackTrace();
        }
    }

}
