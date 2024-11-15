package com.secure.notes.controllers;

import com.secure.notes.models.Note;
import com.secure.notes.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NoteController {

    @Autowired
    private NoteService noteService;

    @PostMapping()
    public Note createNote(@RequestBody String content,
            // gives information about who is logged in
        @AuthenticationPrincipal UserDetails userDetails){
        String username =userDetails.getUsername();
        System.out.println("User Details: "+username);
        return noteService.createNoteForUser(username, content);
    }

//    This method is created because we required notes of only current logged in user
    @GetMapping
    // gives information about who is logged in
    public List<Note> getUserNotes(@AuthenticationPrincipal UserDetails userDetails) {
        String username =userDetails.getUsername();
        System.out.println("User Details: "+username);
        return noteService.getNotesForUser(username);
    }

    @PutMapping("/{noteId}")
    public Note updateNote(@PathVariable Long noteId,
                           @RequestBody String content,
                           // gives information about who is logged in
                           @AuthenticationPrincipal UserDetails userDetails) {
        String username =userDetails.getUsername();
        return noteService.updateNoteForUser(noteId,content,username);
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable Long noteId,
                           // gives information about who is logged in
                           @AuthenticationPrincipal UserDetails userDetails) {
        String username =userDetails.getUsername();
        noteService.deleteNoteForUser(noteId,username);
    }

}
