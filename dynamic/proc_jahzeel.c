#include "../rpc.h" 
#include <stdlib.h> 
#include <stdio.h> 
#include <string.h> 

typedef struct {
    reportable_t parent;
    char *plaintext;   // Cadena de texto en claro
    char *ciphertext;  // Cadena de texto cifrada
    int key;           // Clave para el cifrado/descifrado
} my_struct_t;

void *parse_parameters(void *data)
{
    const char *buf = (const char *)(data); 

    my_struct_t *d = (my_struct_t *)(malloc(sizeof(my_struct_t))); // Asigna memoria dinámicamente para "my_struct_t"

    if (d) 
    {
        // Lee la clave y el texto en claro del buffer de entrada utilizando sscanf
        sscanf(buf, "%d %s", &d->key, buf);
        d->plaintext = strdup(buf); // Almacena el texto en claro en la estructura
    }

    return (void *)d; 
}
//a función que realiza el cifrado César de un texto en claro utilizando una clave dada. 
//se recorre carácter por carácter y se aplica una transformación para obtener el texto cifrado
void *do_work(void *data)
{
    my_struct_t *d = (my_struct_t *)(data); // Convierte el parámetro "data" a un puntero a "my_struct_t"

    int i;
    int len = strlen(d->plaintext);
    d->ciphertext = strdup(d->plaintext);

    for (i = 0; i < len; i++) {
        char c = d->plaintext[i];
        if (c >= 'a' && c <= 'z') {
            d->ciphertext[i] = 'a' + (c - 'a' + d->key) % 26;
        } else if (c >= 'A' && c <= 'Z') {
            d->ciphertext[i] = 'A' + (c - 'A' + d->key) % 26;
        }
    }

    return data; // Devuelve el parámetro "data"
}

reportable_t *report(void *data)
{
    my_struct_t *d = (my_struct_t *)(data); 

    d->parent.data = (char *)(malloc(255 * sizeof(char))); 

    snprintf(d->parent.data, 255, "Ciphertext: %s\n", d->ciphertext); // Crea una cadena de caracteres que informa el resultado del cifrado y la almacena en "parent.data"
    d->parent.len = strlen(d->parent.data); 
    return (reportable_t *)(data); 
}

void clean_up(void *params, void *result, reportable_t *report)
{
    if (report && report->data) 
    {
        free(report->data); 
    }

    if (params)
    {
        my_struct_t *d = (my_struct_t *)(params);
        free(d->plaintext);
        free(d->ciphertext);
        free(params); 
    }

    if (result)
    {
        free(result); 
    }
}