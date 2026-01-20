package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.chave.EscritorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * <b>Segunda etapa - gerar chaves assimétricas</b>
 * <p>
 * A partir dessa etapa, tudo que será feito envolve criptografia assimétrica.
 * A tarefa aqui é parecida com a etapa anterior, pois refere-se apenas a
 * criar e armazenar chaves, mas nesse caso será usado um algoritmo de
 * criptografia assimétrica, o ECDSA.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um par de chaves usando o algoritmo ECDSA com o tamanho de 256 bits;
 * </li>
 * <li>
 * gerar outro par de chaves, mas com o tamanho de 521 bits. Note que esse
 * par de chaves será para a AC-Raiz;
 * </li>
 * <li>
 * armazenar em disco os pares de chaves em formato PEM.
 * </li>
 * </ul>
 */
public class SegundaEtapa {

    public static void executarEtapa() {
        // TODO implementar
        try {
            GeradorDeChaves chaves256 = new GeradorDeChaves(algoritmoChave);
            KeyPair par256 = chaves256.gerarParDeChaves(256);
            EscritorDeChaves.escreveChaveEmDisco(par256.getPublic(), caminhoChavePublicaUsuario);
            EscritorDeChaves.escreveChaveEmDisco(par256.getPrivate(), caminhoChavePrivadaUsuario);

            GeradorDeChaves chaves521 = new GeradorDeChaves(algoritmoChave);
            KeyPair par521 = chaves521.gerarParDeChaves(521);
            EscritorDeChaves.escreveChaveEmDisco(par521.getPublic(), caminhoChavePublicaAc);
            EscritorDeChaves.escreveChaveEmDisco(par521.getPrivate(), caminhoChavePrivadaAc);

            System.out.println("Etapa 2 check");

        } catch (NoSuchAlgorithmException e){
            System.err.println("Erro ao gerar chaves");
            e.printStackTrace();
        }
    }

}
