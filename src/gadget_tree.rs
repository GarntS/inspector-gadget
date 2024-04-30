/*  file:   gadget_tree.rs
    author: garnt
    date:   04/16/2024
    desc:   Tree implementation that stores gadget start addresses at the start
            of gadgets and stores byte sequences instead of human-readable
            strings.
*/

//! gadget_tree contains the [`GadgetTree`] data structure, used to efficiently
//! store and deduplicate gadgets.

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::slice;

/// Tree implementation that stores gadgets and their start addresses. Each
/// node in the tree stores a single instruction's opcode bytes and any
/// addresses at which a gadget that begins with the instruction is located.
/// Instructions are in reverse sequence from top to bottom as they appear in
/// gadgets, with each unique terminating instruction acting as the roots of the
/// tree. The tree and its function are implemented with minimal copying.
pub struct GadgetTree {
    /// [`Vec<T>`] that stores the tree's root nodes.
    roots: Vec<TreeNode>,
    /// The number of gadgets stored in the tree.
    n_gadgets: usize,
}

/// A node in the gadget tree. This struct and its functions are only used to
/// implement the tree and cannot be used directly, [`GadgetTree`] wraps its
/// functionality and should be used as the external interface.
struct TreeNode {
    /// [`Box`]ed [`prim@slice`] of bytes containing a single instruction's
    /// opcode.
    instr_bytes: Box<[u8]>,
    /// [`Vec<T>`] that stores this node's child nodes.
    children: Vec<TreeNode>,
    /// [`Vec<T>`] that stores addresses where gadgets which begin with the
    /// instruction represented by this node is located.
    start_addrs: Vec<usize>,
}

// GadgetTree method impls
impl GadgetTree {
    /// Constructs a new, empty, [`GadgetTree`].
    pub fn new() -> Self {
        GadgetTree {
            roots: Vec::new(),
            n_gadgets: 0,
        }
    }

    /// Returns the number of gadgets stored in this [`GadgetTree`].
    pub fn size(&self) -> usize {
        self.n_gadgets
    }

    /// Walks the tree and returns a [`Vec<T>`] of pairs of
    /// (byte_str, slice of start addresses) for each unique gadget stored
    /// in the tree.
    pub fn walk_gadgets(&self) -> Vec<(Vec<u8>, &[usize])> {
        // walk each root, collecting all gadgets into a single Vec, and return.
        self.roots
            .iter()
            .map(|root| root.walk_gadgets())
            .flatten()
            .collect()
    }

    /// Inserts a new (gadget, addr) pair into the tree.
    pub fn insert<'a>(&mut self, gadget: &mut Vec<&[u8]>, addr: usize) -> usize {
        // the gadget should never be empty
        assert!(!gadget.is_empty());

        // increment the tree size
        self.n_gadgets += 1;

        // grab the next instruction
        let cur_insn_bytes: &[u8] = gadget.pop().unwrap();

        // if a child matches the current instruction, recurse
        if let Some(matching_child) = self
            .roots
            .iter_mut()
            .find(|child| child.instr_bytes.as_ref() == cur_insn_bytes)
        {
            matching_child.insert(gadget, slice::from_ref(&addr));
            return self.n_gadgets;
        // otherwise, recurse
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
    /// Recursively walks this [`TreeNode`] and returns a [`Vec<T>`] of pairs
    /// of (byte_str, slice of start addresses) for each unique gadget stored
    /// in the tree.
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
                self.start_addrs.as_slice(),
            ));
        }

        // otherwise, iterate over the child nodes in parallel
        gadgets.append(
            &mut self
                .children
                .par_iter()
                // call walk_gadgets() for each child
                .map(|child| child.walk_gadgets())
                .flatten()
                // append this node's byte_str to the pair
                .map(|mut pair| {
                    pair.0.extend_from_slice(&self.instr_bytes);
                    pair
                })
                .collect(),
        );

        // return the list of gadgets
        gadgets
    }

    /// Inserts a new (byte_str of each instruction, address) pair into the
    /// tree.
    fn insert(&mut self, gadget: &mut Vec<&[u8]>, addrs: &[usize]) {
        // if the current instruction was the last, add the new start
        // addresses to this node and return
        if gadget.is_empty() {
            self.start_addrs.extend_from_slice(addrs);
            return;
        }

        // grab the next instruction
        let cur_insn_bytes: &[u8] = gadget.pop().unwrap();

        // if a child matches the current instruction, recurse
        if let Some(matching_child) = self
            .children
            .iter_mut()
            .find(|child| child.instr_bytes.as_ref() == cur_insn_bytes)
        {
            matching_child.insert(gadget, addrs);
            return;
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
