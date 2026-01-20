package br.ufsc.labsec.pbad.hiring;

import br.ufsc.labsec.pbad.hiring.etapas.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Classe principal, responsável por executar todas as etapas.
 */

public class ExecutarEtapas {

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        PrimeiraEtapa.executarEtapa();
        SegundaEtapa.executarEtapa();
        TerceiraEtapa.executarEtapa();
        QuartaEtapa.executarEtapa();
        QuintaEtapa.executarEtapa();
        SextaEtapa.executarEtapa();

    }

}
