#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <string.h>

#define IMG_SIZE 28
#define BLEN 16
#define N_LABELS 10
#define N_IMAGES 4 /////////////////////////

LweSample* cypher_data[N_IMAGES][IMG_SIZE][IMG_SIZE];
LweSample* cypher_label[N_IMAGES][N_LABELS];

int main(){
	//generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    printf("Starting process...\n");
    
    FILE* fpx = fopen("train_x.txt", "r");
    FILE* fpy = fopen("train_y.txt", "r");
    int n, i, j, k, l;
    for(n=0; n<N_IMAGES; n++){
    	printf("Encrypting image %d\n", n+1);
    	for(i=0; i<IMG_SIZE; i++){
    		for(j=0; j<IMG_SIZE; j++){
    			int a;
    			fscanf(fpx, "%d", &a);
    			printf("%d ", a);
    			cypher_data[n][i][j] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
    			for(k=0; k<BLEN; k++)
    				bootsSymEncrypt(&cypher_data[n][i][j][k],(a>>k)&1,key);
    		}
    		printf("\n");
    	}

		int b;
		fscanf(fpy, "%d", &b);
		printf("label = %d\n", b);
		for(l=0; l<N_LABELS; l++){
			cypher_label[n][l] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
			if(b == l){
				int c = 1000;
				for(k=0; k<BLEN; k++)
					bootsSymEncrypt(&cypher_label[n][l][k],(c>>k)&1,key);
			}
			else{
				int c = 0;
				for(k=0; k<BLEN; k++)
					bootsSymEncrypt(&cypher_label[n][l][k],(c>>k)&1,key);
			}
		}
    }
    fclose(fpx);
    fclose(fpy);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
    
    //export the training features (x) and labels
    FILE* x_data = fopen("x_data.data", "wb");
    FILE* y_data = fopen("y_data.data", "wb");
    for(n=0; n<N_IMAGES; n++){
    	printf("Saving image %d\n", n);
    	for(i=0; i<IMG_SIZE; i++){
    		for(j=0; j<IMG_SIZE; j++){
    			for(k=0; k<BLEN; k++)
	    			export_gate_bootstrapping_ciphertext_toFile(x_data, &cypher_data[n][i][j][k],params);
    		}
    	}

    	for(l=0; l<N_LABELS; l++){
    		for(k=0; k<BLEN; k++)
	    		export_gate_bootstrapping_ciphertext_toFile(y_data, &cypher_label[n][l][k],params);
    	}
    }
    fclose(x_data);
    fclose(y_data);

    //clean up all pointer
    printf("Cleaning up pointers\n");
    for(n=0; n<N_IMAGES; n++){
    	for(i=0; i<IMG_SIZE; i++)
    		for(j=0; j<IMG_SIZE; j++)
    			delete_gate_bootstrapping_ciphertext_array(BLEN, cypher_data[n][i][j]);

    	for(l=0; l<N_LABELS; l++)
    		delete_gate_bootstrapping_ciphertext_array(BLEN, cypher_label[n][l]);
    }
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}