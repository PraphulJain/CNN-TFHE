#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>

#define IMG_SIZE 28
#define BLEN 16
#define N_LABELS 10
#define N_IMAGES 4
#define N_EPOCHS 1
#define KERNEL 2
#define PADDING 0
#define STRIDES 8


void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp4=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp5=new_gate_bootstrapping_ciphertext_array(1,bk->params);

    bootsXOR(temp1, a, b, bk);  //a xorb
    bootsXOR(result,temp1,lsb_carry,bk);  //a xor b xor ci
    
    bootsNOT(temp4,a,bk);  // complement of a
    bootsAND(temp3,temp4,b,bk); // complement a and b

    bootsNOT(temp5,temp1,bk);  // complement of a XOR b

    bootsAND(temp2,temp5,lsb_carry,bk);// complement of a XOR b AND lasb_carry
  
    bootsOR(tmp,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry,tmp,bk);
}

void subtract(LweSample* result, LweSample* tmps, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    //run the elementary comparator gate n times//
      
  	for (int i=0; i<nb_bits; i++){
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
}

void Addition(LweSample* top1, const LweSample* a6, const LweSample* b6, LweSample* lsb_carry1, LweSample* tmp6, const 	TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    
    bootsXOR(temp1, a6, b6, bk);  //a xor b  
    bootsXOR(top1,temp1,lsb_carry1,bk);  //a xor b xor ci
    bootsAND(temp2,temp1,lsb_carry1,bk);   //ci and (a xor b)
    bootsAND(temp3,a6,b6,bk);             // a and b 
    bootsOR(tmp6,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry1,tmp6,bk);


}
void Adder(LweSample* top1, const LweSample* a6, const LweSample* b6, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
	LweSample* tmps6 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	bootsCONSTANT(&tmps6[0], 0, bk); //initialize carry to 0

    //run the elementary comparator gate n times//
        
	for (int i=0; i<nb_bits; i++){
        Addition(&top1[i], &a6[i], &b6[i], &tmps6[0], &tmps6[1], bk);
    }
    delete_gate_bootstrapping_ciphertext_array(2, tmps6);    
}

void multiplexer(LweSample* rdbdata,LweSample* a,LweSample* b,LweSample* select_line,const int nb_bit, const TFheGateBootstrappingCloudKeySet* bk){
    int m=0;
    for(int i=0;i<nb_bit;i++){
    	bootsMUX(&rdbdata[i],&select_line[m],&b[i],&a[i],bk);
    }
}

void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
        
    LweSample* enc_theta=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    for(int i=0;i<nb_bits;i++){ //initialize theta to all zero bits
        bootsCONSTANT(&enc_theta[i],0,bk);
    }
    for(int i=0;i<2*nb_bits;i++){ //initialize product to all zero bits
        bootsCONSTANT(&product[i],0,bk);
    } 

    for (int i=0; i<nb_bits; i++) {
        LweSample* temp_result=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        LweSample* partial_sum=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        for(int j=0;j<2*nb_bits;j++){ //initialize temp_result to all zero bits
	        bootsCONSTANT(&temp_result[j],0,bk);
	        bootsCONSTANT(&partial_sum[j],0,bk);
        } 
        LweSample* temp2=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
        multiplexer(temp2,enc_theta,a,&b[i],nb_bits,bk);
        for(int j=0;j<nb_bits;j++){ 
        	bootsCOPY(&temp_result[i+j],&temp2[j],bk);
        }

        //Add the valid result to partial_sum//
        Adder(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
        	bootsCOPY(&product[j],&partial_sum[j],bk);
        }
    }
}

void is_equal(LweSample* equal, LweSample* a, LweSample* b, const int n_bits, const TFheGateBootstrappingCloudKeySet* bk){
	int i;
	LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	bootsCONSTANT(&equal[0],0,bk);
	bootsCONSTANT(temp2,0,bk);
	for(i=0; i<n_bits; i++){
		bootsXOR(temp1, &a[i], &b[i], bk);
		bootsOR(temp3, temp2, temp1, bk);
		bootsCOPY(temp2, temp3, bk);
		bootsNOT(&equal[0], temp3, bk);
	}
}

///////////////////////////////////////////////

void forward_convolution(int blen, int k_size, int padding, int strides, int x_size, int out_size, LweSample* x[x_size][x_size], LweSample* conv_wt[k_size][k_size], LweSample* out[out_size][out_size], const TFheGateBootstrappingCloudKeySet* bk, TFheGateBootstrappingSecretKeySet* key){
	int row, col;
	printf("Conv layer output without activation function:\n");
	//This is just for padding = 0
	#pragma omp parallel for default(none) private(row, col) shared(k_size, strides, x_size, x, out, conv_wt, bk, blen)
		for(row=0; row<x_size-k_size+1; row+=strides){
			for(col=0; col<x_size-k_size+1; col+=strides){
				int i, j, k;

				out[(int)(row/strides)][(int)(col/strides)] = new_gate_bootstrapping_ciphertext_array(2*blen, bk->params);
				for(k=0; k<2*blen; k++)
					bootsCONSTANT(&out[(int)(row/strides)][(int)(col/strides)][k], 0, bk);

				for(i=0; i<k_size; i++){
					for(j=0; j<k_size; j++){
						LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(2*blen, bk->params);
						LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(2*blen, bk->params);
						printf("row %d col %d i %d j %d\n", row, col, i, j);
						
						multiply(temp1, x[row+i][col+j], conv_wt[i][j], blen, bk);
						//normalize(temp1, norm);
						Adder(temp2, out[(int)(row/strides)][(int)(col/strides)], temp1, 2*blen, bk);
						
						for(k=0; k<2*blen; k++){
							bootsCOPY(&out[(int)(row/strides)][(int)(col/strides)][k], &temp2[k], bk);
						}
					}
				}
			}
		}
	
	//////////////////Decrypting
	int i, j, k;
	for(i=0; i<out_size; i++){   //out_size
		for(j=0; j<out_size; j++){
			int a = 0;
			int base = 1;
			for(k=0; k<2*blen; k++){
				int ai = bootsSymDecrypt(&out[i][j][k], key)>0;
				a += base*ai;
				base = base*2;
			}
			printf("%d ", a);
		}
		printf("\n");
	}
	/////////////////////////////
}

void train(int blen, int n_images, int image_size, int n_labels, int epochs, int k_size, int padding, int strides, LweSample* x_data[n_images][image_size][image_size], LweSample* y_data[n_images][n_labels], const TFheGateBootstrappingCloudKeySet* bk, TFheGateBootstrappingSecretKeySet* key){
	int epoch, i, j, k;
	int conv_out_size = ((int)((image_size-k_size+2*padding)/strides))+1;

	//Initialize weights
	LweSample* conv_wt[k_size][k_size];
	LweSample* conv_out[conv_out_size][conv_out_size];

	printf("Initial weights:\n");
	for(i=0; i<k_size; i++){
		for(j=0; j<k_size; j++){
			conv_wt[i][j] = new_gate_bootstrapping_ciphertext_array(blen, bk->params);
			//////////////////Decrypting
			int a = 0;
			int base = 1;
			//////////////////
			for(k=0; k<blen; k++){
				if(k==0)
					bootsCONSTANT(&conv_wt[i][j][k], 1, bk);
				else
					bootsCONSTANT(&conv_wt[i][j][k], 0, bk);

				//////////////////Decrypting
				int ai = bootsSymDecrypt(&conv_wt[i][j][k], key)>0;
				a += base*ai;
				base = base*2;
				//////////////////
			}
			printf("%d ", a);
		}
		printf("\n");
	}

	for(epoch=0; epoch<N_EPOCHS; epoch++){
		//AT LAST PUT LOOP TO DO THIS FOR ALL SAMPLES
		time_t st_time = clock();
		time_t s = time(NULL);
		struct tm* start_time = localtime(&s);
		printf("Forward prop start time: %02d:%02d:%02d\n", start_time->tm_hour, start_time->tm_min, start_time->tm_sec);
    	forward_convolution(blen, k_size, padding, strides, image_size, conv_out_size, x_data[0], conv_wt, conv_out, bk, key);
    	time_t en_time = clock();
    	s = time(NULL);
    	struct tm* end_time = localtime(&s);
    	printf("Time to execute forward prop for 1 data point = %ld seconds\n", (en_time-st_time)/1000000);
    	printf("Forward prop end time: %02d:%02d:%02d\n", end_time->tm_hour, end_time->tm_min, end_time->tm_sec);
    } 
}


////////////////////////////////////

LweSample* x_data[N_IMAGES][IMG_SIZE][IMG_SIZE];
LweSample* y_data[N_IMAGES][N_LABELS];

void main(){
	printf("Reading the key...\n");

    //Reading the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //Params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //Reading the cloud data (labels and features)
    printf("Reading the features and labels...\n");
    FILE* dataxf = fopen("x_data.data","rb");
    FILE* datayf = fopen("y_data.data","rb");
    int n, i, j, k, l;
    for(n=0; n<N_IMAGES; n++){
    	for(i=0; i<IMG_SIZE; i++){
    		for(j=0; j<IMG_SIZE; j++){
    			x_data[n][i][j] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
    			for(k=0; k<BLEN; k++)
    				import_gate_bootstrapping_ciphertext_fromFile(dataxf, &x_data[n][i][j][k], params);
    		}
    	}

    	for(l=0; l<N_LABELS; l++){
    		y_data[n][l] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
    		for(k=0; k<BLEN; k++)
    			import_gate_bootstrapping_ciphertext_fromFile(datayf, &y_data[n][l][k], params);
    	}
    }
    fclose(dataxf);
    fclose(datayf);

    ////////////////////////////For Verification
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    ///////////////////////////////////////

    //Implementation of model
    //Training
    train(BLEN, N_IMAGES, IMG_SIZE, N_LABELS, N_EPOCHS, KERNEL, PADDING, STRIDES, x_data, y_data, bk, key);
    //deleting arrays
    for(n=0; n<N_IMAGES; n++){
    	for(i=0; i<IMG_SIZE; i++)
    		for(j=0; j<IMG_SIZE; j++)
    			delete_gate_bootstrapping_ciphertext_array(BLEN,x_data[n][i][j]);
    	
    	for(l=0; l<N_LABELS; l++)
    		delete_gate_bootstrapping_ciphertext_array(BLEN,y_data[n][l]);
    }
}
