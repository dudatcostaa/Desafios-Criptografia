package labsec;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import static labsec.C2.hexToDec;
import static labsec.C3.arrayIntToString;

/**
 *
 * @author mariaeduardateixeiracosta
 */

/* Algoritmo: usar método do exercício 3 e realizar a leitura do arquivo*/

public class C4 {
    
    public static void main(String[] args) throws FileNotFoundException{
        
        int melhorPontuacao = -1;
        int melhorChave = -1;
        String melhorTexto = "";
               
        try{
            BufferedReader arquivo = new BufferedReader(new FileReader("arquivo.txt"));
            String linha = arquivo.readLine();
            
            while (linha != null){
                int[] cifra = hexToDec(linha);
                
                for (int chave = 0; chave < 256; chave++){
                    int[] resultado = new int[cifra.length];
                    
                    for (int i = 0; i < cifra.length; i++){
                        resultado[i] = cifra[i] ^ chave;
                    }
                    
                    String tentativa = arrayIntToString(resultado);
                    
                    int p = C3.pontuacao(tentativa);
                    
                    if (p > melhorPontuacao){
                        melhorPontuacao = p;
                        melhorChave = chave;
                        melhorTexto = tentativa;
                    }
                }
                
                linha = arquivo.readLine();
            }
            
            System.out.println(melhorChave);
            System.out.println(melhorTexto);
            
            arquivo.close();
            
        } catch (IOException e){
            e.printStackTrace();
        }
    }
    
}
