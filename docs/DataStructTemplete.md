---
title: DataStructTemplete
widgets:
  - type: toc
    position: left
    index: true
    collapsed: true
    depth: 3
toc: true
date: 2024-11-06 12:48:42
tags:
cover:
---

以下模板皆由C語言實作

# Binary Search Tree
```c
#include<stdio.h>
#include<stdlib.h>

struct BST{
	struct BST *left;
	struct BST *right;
	int val;
};
typedef struct BST BST;

BST* MinValueNode(BST* root){
	BST* current = root;
	while(current && current ->left != NULL){
		current = current->left;
	}
	return current;
}

BST* searchNode(BST* root, int data) {
    if (root == NULL || root->val == data) {
        return root;
    }
    if (data < root->val) {
        return searchNode(root->left, data);
    } else {
        return searchNode(root->right, data);
    }
}


BST* deleteNode(BST *root,int n){
	if(root == NULL)return root;
	if(n < root->val){
		root->left = deleteNode(root->left,n);
	}else if(n > root->val){
		root->right = deleteNode(root->right,n);
	}
	else{
		if(root->left == NULL){
			BST* nextNode = root->right;
			free(root);
			return nextNode;	
		}else if(root->right == NULL){
			BST* nextNode = root->left;
			free(root);
			return nextNode;
		}
		BST *SuccessorNode = MinValueNode(root->right);
		root->val = SuccessorNode->val;
		root->right = deleteNode(root->right,SuccessorNode->val);
	}
	return root;
}



BST* insertNode(BST *root,int n){
	if(root == NULL){
		BST* newNode = (BST *)malloc(sizeof(BST));
		newNode->val = n;
		newNode->left = NULL;
		newNode->right = NULL;
		root = newNode;
		return root;
	}
	if( n > root ->val){
		root->right = insertNode(root->right,n);
	}else if(n < root->val){
		root->left = insertNode(root->left,n);
	}
	return root;
}

void PrintTree(BST *root){
	if(root == NULL)return;
	PrintTree(root->left);
	printf("%d ",root->val);
	PrintTree(root->right);
}

int main(){
	BST *root = NULL;
	root = insertNode(root,1);
	root = insertNode(root,5);
	root = insertNode(root,10);
	root = insertNode(root,100);
	root = insertNode(root,25);
	
	root = deleteNode(root,10);
	
	PrintTree(root);
	
	
}
```

# Disjoint set

```c
struct Disjoint_set{
    int d[MAXNUM],num[MAXNUM];
    void array_set(int n){
        for(int i=1;i<=n;i++){
            d[i]=i;
            num[i]=1;
        }
    }
    int find(int n){
        if(n!=d[n]){
            return d[n]=find(d[n]);
        }else{
            return n;
        }
    }
    int Union(int x,int y){
        x=find(x);
        y=find(y);
        if(x==y)return 0;
        if(num[x]>num[y])swap(x,y);
        num[y]+=num[x];
        d[x]=y;
        return 1;
    }
}DS;
```