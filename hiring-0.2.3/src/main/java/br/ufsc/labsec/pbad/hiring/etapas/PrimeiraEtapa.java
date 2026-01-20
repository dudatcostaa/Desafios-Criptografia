package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.resumo.Resumidor;

import java.io.File;
import java.io.IOException;

/**
 * <b>Primeira etapa - obter o resumo criptográfico de um documento</b>
 * <p>
 * Basta obter o resumo criptográfico do documento {@code textoPlano.txt}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * obter o resumo criptográfico do documento, especificado na descrição
 * dessa etapa, usando o algoritmo de resumo criptográfico conhecido por
 * SHA-256;
 * </li>
 * <li>
 * armazenar em disco o arquivo contendo o resultado do resumo criptográfico,
 * em formato hexadecimal.
 * </li>
 * </ul>
 *
 * Algoritmo:
 * Criar instância
 * Criar referência
 * Obter o resumo
 * Armazenar no disco
 * Exceções
 */
public class PrimeiraEtapa {

    public static void executarEtapa() {
        try {
            Resumidor r = new Resumidor();

            File input = new File(Constantes.caminhoTextoPlano);

            byte[] resumo = r.resumir(input);

            r.escreveResumoEmDisco(resumo, Constantes.caminhoResumoCriptografico);

            System.out.println("Etapa 1 check");

        } catch (IOException e) {
            System.err.println("Erro ao armazenar o resumo");
            e.printStackTrace();
        }

    }

}
