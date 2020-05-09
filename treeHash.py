from math import pow
from ADRS import *
from XMSSPrivateKey import *
from ltree import *
from generate_pk_kuglan import *


def treeHash(SK: XMSSPrivateKey, s: int, t: int, adrs: ADRS, w: int in {4, 16}, length_all: int) -> bytearray:

    Stack = []

    if s % (1 << t) != 0:
        return -1

    for i in range(0, int(pow(2, t))):
        SEED = SK.getSEED()
        adrs.setType(0)
        adrs.setOTSAddress(s + i)
        pk = WOTS_genPK(SK.getWOTS_SK(s + i), length_all, w, SEED, adrs)
        adrs.setType(1)
        adrs.setLTreeAddress(s + i)
        node = ltree(pk, adrs, SEED, length_all)  # leaf -> height is 0

        node_as_stack_element = StackElement(node, 0)  # wrap node into StackElement to store height with node in Stack

        adrs.setType(2)
        adrs.setTreeHeight(0)
        adrs.setTreeIndex(i + s)

        # check whether stack is not empty and top of stack node has height equal to current node
        # traversing elements of tree, starting at left bottom leaf and calculating sum of siblings
        while len(Stack) != 0 and Stack[len(Stack) - 1].get_height() == node_as_stack_element.get_height():
            adrs.setTreeIndex(int((int.from_bytes(adrs.getTreeHeight(), byteorder='big') - 1) / 2))

            previous_height = node_as_stack_element.get_height()  # get height of offspring

            node = RAND_HASH(Stack.pop().get_node(), node_as_stack_element.get_node(), SEED, adrs)

            node_as_stack_element = StackElement(node, previous_height + 1)  # wrap and assign height = height of offspring + 1

            adrs.setTreeHeight(int.from_bytes(adrs.getTreeHeight(), byteorder='big') + 1)

        Stack.append(node_as_stack_element)

    return Stack.pop().get_node()  # returns root element of tree


class StackElement:
    def __init__(self, node_value=None, height=None):
        self.node_value = node_value
        self.height_of_node = height

    def set_node(self, node_value):
        self.node_value = node_value

    def get_node(self):
        return self.node_value

    def set_height(self, height):
        self.height_of_node = height

    def get_height(self):
        return self.height_of_node