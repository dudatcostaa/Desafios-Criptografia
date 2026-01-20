package labsec;

/**
 *
 * @author mariaeduardateixeiracosta
 */

/* Algoritmo: separar a string em pares
                       passar para binário de 8 bits
                       separar esses bytes em conjuntos de 6 bits (base64 usa separacao de 6 bits)
                       passar para decimal
*/

public class C1{
    private static final String BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    public static void hexToDec(String input){
        StringBuilder stringBinaria = new StringBuilder();
        
        for (int i = 0; i < input.length(); i += 2){
            String pares = input.substring(i, i + 2);
            int valorDecimal = Integer.parseInt(pares, 16); //hexa - dec
            String valorBinario = String.format("%8s", Integer.toBinaryString(valorDecimal)).replace(" ", "0");
            stringBinaria.append(valorBinario);
        }
        
        while(stringBinaria.length() % 6 != 0){
            stringBinaria.append("0");
        }
        
        StringBuilder resultado = new StringBuilder();
        for (int i = 0; i <= stringBinaria.length() - 6; i += 6){
            String grupos6Bits = stringBinaria.substring(i, i + 6);
            int decimal = Integer.parseInt(grupos6Bits, 2);
            char paraCar64 = BASE64_TABLE.charAt(decimal);
            resultado.append(paraCar64);
        }
        
        int mod = resultado.length() % 4;
        if (mod != 0) {
            for (int i = 0; i < 4 - mod; i++) {
                resultado.append('=');
            }
        }

        System.out.println(resultado);
    }
    
    public static void main(String[] args) {  // teste
        hexToDec("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");  
    }
}

    
