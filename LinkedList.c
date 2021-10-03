#include <stdio.h>
#include <stdlib.h>
#include "LinkedList.h"

void init(LinkedList *list) { //Rosangela
    list->first=NULL;
    list->size=0;
}

bool isEmpty(LinkedList *list) { //Rosangela
    return (list->size==0);
}

int enqueue(LinkedList *list, void *data) { //Rosangela
    Node *newNode = (Node*)malloc(sizeof(Node));
    if (newNode==NULL) return -1;
    newNode->data = data;
    newNode->next = NULL;
    if (isEmpty(list))            //se a lista estiver vazia
        list->first = newNode;    //novo nó é o primeiro
    else {
        Node *aux = list->first;  //aux aponta para o primeiro
        while (aux->next != NULL) //enquanto não for o último nó
            aux = aux->next;      //aux avança para o nó seguinte
        aux->next = newNode;      //último nó aponta para o novo nó
    }
    list->size++;
    return 1;
}
