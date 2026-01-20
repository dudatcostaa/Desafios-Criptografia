package br.ufsc.labsec.pbad.hiring.criptografia.resumo;

import br.ufsc.labsec.pbad.hiring.Constantes;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Classe responsável por executar a função de resumo criptográfico.
 *
 * @see MessageDigest
 */
public class Resumidor {

    private MessageDigest md;
    private String algoritmo;

    /**
     * Construtor.
     * Inicializar os atributos da classe
     * Criar o objeto MessageDigest
     */
    public Resumidor() {
        this.algoritmo = Constantes.algoritmoResumo;
        try {
            this.md = MessageDigest.getInstance(this.algoritmo); //https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param arquivoDeEntrada arquivo a ser processado.
     * @return Bytes do resumo.
     *
     * Algoritmo:
     * ler os bytes do arquivo e colocar em um array
     * atualizar o MessageDigest
     *
     */
    public byte[] resumir(File arquivoDeEntrada) {
        try {
            byte[] arrayConteudo = Files.readAllBytes(arquivoDeEntrada.toPath());
            md.update(arrayConteudo);
            return md.digest();
        } catch (IOException e) {
            throw new RuntimeException("Erro ao ler arquivo", e);
        }
    }

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     *
     * Algoritmo:
     *  Criar um StringBuilder
     *  Adicionar os bytes no StringBuilder
     *  formatar, %, 0 - preencher com 0 à esquerda, 2 - n caracteres, x - hexadecimal
     *  Colocar o builder em uma nova variável
     *  Criar um writer
     */
    public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) throws IOException {

        StringBuilder resumoHexBuilder = new StringBuilder();
        for (byte b : resumo) {
            resumoHexBuilder.append(String.format("%02x", b));
        }
        String resumoHex = resumoHexBuilder.toString();

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(caminhoArquivo))) {
            writer.write(resumoHex);
        }
    }

}
