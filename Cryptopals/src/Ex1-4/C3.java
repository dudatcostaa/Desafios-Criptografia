package labsec;

import static labsec.C2.hexToDec;

/**
 *
 * @author mariaeduardateixeiracosta
 */

/*Algoritmo :  pegar o array com valores inteiros (ascii) e converter para String
                        pegar os caracteres que mais aparecem no inglês e somar na pontuação (maiúsculo, minúsculo e " "
                        tranformar hex pra decimal, passar pelas 256 chaves, quando encontrar uma tentativa melhor atualiza aas variáveis
*/

public class C3 {

    public static String arrayIntToString(int [] array){
        StringBuilder stringArray = new StringBuilder();
        for (int i : array){
            stringArray.append((char) i);
        }
        return stringArray.toString();
    }
    
    public static int pontuacao(String entrada){
        int pontos = 0;
        String comuns = "ETAOIN SHRDLUetaoin shrdlu ";
        for (char i : entrada.toCharArray()){
            if (comuns.indexOf(i) != -1) {
                pontos ++;
            }
        }
        return pontos;
    }
    
    public static void decifrarXorEm1Byte(String hexInput){
        int [] cifra = hexToDec(hexInput);
        
        int melhorPontuacao = -1;
        int melhorChave = -1;
        String melhorTexto = "";
        
        for (int chave = 0; chave < 256; chave ++){ //256 valores do ascii
            int[] resultado = new int [cifra.length];
            for (int i = 0; i < cifra.length; i++){
                resultado[i] = cifra[i] ^chave;
            }
            
             String tentativa = arrayIntToString(resultado);
             
             int p = pontuacao(tentativa);
             
             if (p > melhorPontuacao){
                 melhorPontuacao = p;
                 melhorChave = chave;
                 melhorTexto = tentativa;
             }
        }
        
        System.out.println(melhorChave);
        System.out.println(melhorTexto);
        
    }
    
    public static void main(String[] args){ //teste
            String input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            decifrarXorEm1Byte(input);
        }

}
