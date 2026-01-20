package labsec;

/**
 *
 * @author mariaeduardateixeiracosta
 */

/*Algoritmo: temos valor em hex, quebrar em pares de 2, pegar esses pares e converter pra decimal
                       fazer um xor entre decimais: colocar as duas entradas com os valores convertidos para decimal, e tem que ser do mesmo tamanho
 */

public class C2 {
    
    public static int[] hexToDec(String input){
        int[] resultado = new int[input.length() / 2];
        
        for(int i = 0; i < input.length(); i+=2){
            String pares = input.substring(i, i + 2);
            int valorDecimal = Integer.parseInt(pares, 16);
            resultado[i / 2] = valorDecimal;
        }
        return resultado;
    }
    
    public static String xor(String input1, String input2) {
        
        int[] a = hexToDec(input1);
        int[] b = hexToDec(input2);
        
        if (a.length != b.length){ 
            throw new IllegalArgumentException("String de tamanhos diferentes");
        }
        
        StringBuilder resultadoXor = new StringBuilder();
        
        for (int i = 0; i < a.length; i++){
            int xor = a[i] ^b[i];
            resultadoXor.append(String.format("%02x", xor));
        }
        
        return resultadoXor.toString();
        
    }
    
    public static void main(String[] args) { //teste
        String a = "1c0111001f010100061a024b53535009181c";
        String b = "686974207468652062756c6c277320657965";
        System.out.println(xor(a, b));
    }
    
}