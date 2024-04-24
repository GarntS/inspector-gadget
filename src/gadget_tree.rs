/*  file:       gadget_tree.rs
    author:     garnt
    date:       04/16/2024
    desc:       Tree implementation that stores gadget start addresses at the
                start of gadgets and stores byte sequences instead of
                human-readable strings.
 */

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::slice;

// Tree data structure that sorts byte sequences and stores gadget start
// addresses. The tree and its function are implemented with minimal copying.
pub struct GadgetTree {
    // root tree nodes
    roots: Vec<TreeNode>,
    // # of gadgets stored in the tree
    n_gadgets: usize,
}

// A node in the gadget tree. This struct and its functions should not be used
// directly, GadgetTree wraps this functionality and should be used instead.
struct TreeNode {
    // bytes for this node in the tree
    instr_bytes: Box<[u8]>,
    // child nodes
    children: Vec<TreeNode>,
    // addresses at which a gadget for which this node contains the *ending*
    // bytes is located.
    start_addrs: Vec<usize>,
}

// GadgetTree method impls
impl GadgetTree {
    // new() constructs a new, empty, GadgetTree
    pub fn new() -> Self {
        GadgetTree {
            roots: Vec::new(),
            n_gadgets: 0,
        }
    }

    // size() returns the number of gadgets stored within the tree.
    pub fn size(&self) -> usize {
        self.n_gadgets
    }

    // walk_gadgets() walks the tree and returns a vec of pairs of
    // (byte_str, <slice of start addresses>) for each unique gadget.
    pub fn walk_gadgets(&self) -> Vec<(Vec<u8>, &[usize])> {
        // walk each root, collecting all gadgets into a single Vec, and return.
        self.roots.iter().map(|root| root.walk_gadgets()).flatten().collect()
    }

    // insert() inserts a new (gadget, addr) pair into the tree.
    pub fn insert<'a>(&mut self, gadget: &mut Vec<&[u8]>, addr: usize) -> usize {
        // the gadget should never be empty
        assert!(!gadget.is_empty());

        // increment the tree size
        self.n_gadgets += 1;

        // grab the next instruction
        let cur_insn_bytes: &[u8] = gadget.pop().unwrap();

        // if a child matches the current instruction, recurse
        if let Some(matching_child) = self.roots
            .iter_mut()
            .find(|child| child.instr_bytes.as_ref() == cur_insn_bytes) {
            matching_child.insert(gadget, slice::from_ref(&addr));
            return self.n_gadgets
        // otherwise, 
        // recurse
        } else {
            // create a new child node for the current instruction and recurse
            let mut new_root = TreeNode {
                instr_bytes: Box::from(cur_insn_bytes),
                children: Vec::new(),
                start_addrs: Vec::new(),
            };
            new_root.insert(gadget, slice::from_ref(&addr));

            // add the new root to the list of roots
            self.roots.push(new_root)
        }

        // return the new size
        self.n_gadgets
    }
}

// TreeNode method impls
impl TreeNode {
    // walk_gadgets() recursively walks this TreeNode and returns a vec of pairs
    // of (byte_str, <slice of start addresses>) for each unique gadget.
    fn walk_gadgets(&self) -> Vec<(Vec<u8>, &[usize])> {
        // if this node has no children, it should have start_addrs.
        if self.children.is_empty() {
            assert!(!self.start_addrs.is_empty());
        }

        // create a vec to store gadgets in
        let mut gadgets: Vec<(Vec<u8>, &[usize])> = Vec::new();
        if !self.start_addrs.is_empty() {
            gadgets.push((
                self.instr_bytes.clone().to_vec(),
                self.start_addrs.as_slice()
            ));
        }

        // otherwise, iterate over the child nodes in parallel
        gadgets.append(&mut self.children
            .par_iter()
            // call walk_gadgets() for each child
            .map(|child| child.walk_gadgets())
            .flatten()
            // append this node's byte_str to the pair
            .map(|mut pair| {
                pair.0.extend_from_slice(&self.instr_bytes);
                pair
            })
            .collect()
        );

        // return the list of gadgets
        gadgets
    }

    // insert() inserts a new byte string into the tree by splitting
    // a TreeNode into three TreeNodes in a sub-tree, or by inserting a new
    // TreeNode after the parent.
    fn insert(&mut self, gadget: &mut Vec<&[u8]>, addrs: &[usize]) {
        // if the current instruction was the last, add the new start
        // addresses to this node and return
        if gadget.is_empty() {
            self.start_addrs.extend_from_slice(addrs);
            return
        }

        // grab the next instruction
        let cur_insn_bytes: &[u8] = gadget.pop().unwrap();

        // if a child matches the current instruction, recurse
        if let Some(matching_child) = self.children
                .iter_mut()
                .find(|child| child.instr_bytes.as_ref() == cur_insn_bytes) {
            matching_child.insert(gadget, addrs);
            return
        } else {
            // create a new child node for the current instruction and recurse
            let mut new_child = TreeNode {
                instr_bytes: Box::from(cur_insn_bytes),
                children: Vec::new(),
                start_addrs: Vec::new(),
            };
            new_child.insert(gadget, addrs);

            // add the new child node to this node's children
            self.children.push(new_child);
        }
    }
}