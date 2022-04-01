//----------------------------------------------------------------------------
//
// TSDuck - The MPEG Transport Stream Toolkit
// Copyright (c) 2005-2021, Thierry Lelegard
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//
//----------------------------------------------------------------------------
//
//  Transport stream processor shared library:
//  Remove ads insertions from a program using SCTE 35 splice information.
//
//----------------------------------------------------------------------------

#include "tsPluginRepository.h"
#include "tsServiceDiscovery.h"
#include "tsSectionDemux.h"
#include "tsSpliceInformationTable.h"
#include "tsContinuityAnalyzer.h"
#include "tsAlgorithm.h"
TSDUCK_SOURCE;


//----------------------------------------------------------------------------
// Plugin definition
//----------------------------------------------------------------------------

namespace ts {
    class ElementalPlugin:
            public ProcessorPlugin,
            private SectionHandlerInterface,
            private SignalizationHandlerInterface
    {
        TS_NOBUILD_NOCOPY(ElementalPlugin);
    public:
        // Implementation of plugin API
        ElementalPlugin(TSP*);
        virtual bool getOptions() override;
        virtual bool start() override;
        virtual Status processPacket(TSPacket&, TSPacketMetadata&) override;

    private:
        // ------------------------------------------------------------
        // Data Model
        // ------------------------------------------------------------

        // In case of splicing by component, each PID in the service is identified by a component tag.
        // This is a map of component tags, indexed by PID.
        typedef std::map<PID, uint8_t> TagByPID;

        // A reduced form of splice event.
        class Event
        {
        public:
            bool     out;  // When true, this is a "splice out" event, "splice in" otherwise.
            uint32_t id;   // Splice event id, in case of cancelation later.

            // Constructor
            Event(bool out_ = false, uint32_t id_ = 0) : out(out_), id(id_) {}
        };

        // Each PID of the service has a list of splice events, sorted by PTS value.
        // For simplicity, we use a map, indexed by PTS value.
        // If several events have the same PTS, the last one prevails.
        typedef std::map<uint64_t,Event> EventByPTS;

        // State of a PID which is subject to splicing.
        class PIDState
        {
        public:
            PID        pid;                  // PID value.
            bool       currentlyOut;         // PID is currently spliced out.
            uint64_t   outStart;             // When spliced out, PTS value at the time of splicing out.
            uint64_t   totalAdjust;          // Total removed time in PTS units.
            uint64_t   lastPTS;              // Last PTS value in this PID.
            EventByPTS events;               // Ordered map of upcoming slice events.
            bool       immediateOut;         // Currently splicing out for an immediate event
            uint32_t   immediateEventId;     // Event ID associated with immediate splice out event
            bool       cancelImmediateOut;   // Want to cancel current immediate splice out event
            bool       isAudio;              // Associated with audio stream
            bool       isVideo;              // Associated with video stream
            uint64_t   lastOutEnd;           // When spliced back in, PTS value at the time of the splice in
            uint64_t   ptsLastSeekPoint;     // PTS of last seek point for this PID
            uint64_t   ptsBetweenSeekPoints; // PTS difference between last seek points for this PID

            // Constructor
            PIDState(PID = PID_NULL);

            // Remove all splicing events with specified id.
            void cancelEvent(uint32_t event_id);

        };

        // All PID's in the service are described by a map, indexed by PID.
        typedef std::map<PID, PIDState> StateByPID;

        // ------------------------------------------------------------
        // Plugin Implementation
        // ------------------------------------------------------------
        uint32_t           _eventIDFilter;   // Only allow this event_id to pass
        bool               _abort;       // Error (service not found, etc)
        bool               _continue;    // Continue processing if no splice information is found.
        bool               _adjustTime;  // Adjust PTS and DTS time stamps.
        bool               _fixCC;       // Fix continuity counters.
        Status             _dropStatus;  // Status for dropped packets
        ServiceDiscovery   _service;     // Service name & id.
        SectionDemux       _demux;       // Section filter for splice information.
        TagByPID           _tagsByPID;   // Mapping between PID's and component tags in the service.
        StateByPID         _states;      // Map of current state by PID in the service.
        std::set<uint32_t> _eventIDs;    // set of event IDs of interest
        bool               _dryRun;      // Just report what it would do
        PID                _videoPID;    // First video PID, if there is one
        ContinuityAnalyzer _ccFixer;     // To fix continuity counters in spliced PID's.

        // Implementation of interfaces.
        virtual void handleSection(SectionDemux&, const Section&) override;
        virtual void handlePMT(const PMT&, PID) override;
    };
}

TS_REGISTER_PROCESSOR_PLUGIN(u"elemental", ts::ElementalPlugin);


//----------------------------------------------------------------------------
// Constructor
//----------------------------------------------------------------------------

ts::ElementalPlugin::ElementalPlugin(TSP* tsp_) :
        ProcessorPlugin(tsp_, u"Remove ads insertions from a program using SCTE 35 splice information", u"[options] [service]"),
        _eventIDFilter(),  // Only allow this event_id to pass
        _abort(false),
        _continue(false),
        _adjustTime(false),
        _fixCC(false),
        _dropStatus(TSP_DROP),
        _service(duck, this),
        _demux(duck, nullptr, this),
        _tagsByPID(),
        _states(),
        _eventIDs(),
        _dryRun(false),
        _videoPID(PID_NULL),
        _ccFixer(NoPID, tsp)
{
    // We need to define character sets to specify service names.
    duck.defineArgsForCharset(*this);

    option(u"event-id-to-filter", 0, INTEGER,0,1,0,31);
    help(u"event-id-to-filter", u"Only allow this event_id to pass as part of SCTE-35 descriptor");

    option(u"", 0, STRING, 0, 1);
    help(u"",
         u"Specifies the service to modify. If the argument is an integer value (either "
         u"decimal or hexadecimal), it is interpreted as a service id. Otherwise, it "
         u"is interpreted as a service name, as specified in the SDT. The name is not "
         u"case sensitive and blanks are ignored. If the input TS does not contain an "
         u"SDT, use a service id. When omitted, the first service in the PAT is used.");

    option(u"adjust-time", 'a');
    help(u"adjust-time",
         u"Adjust all time stamps (PCR, OPCR, PTS and DTS) after removing splice-out/in sequences. "
         u"This can be necessary to improve the video transition.");

    option(u"continue", 'c');
    help(u"continue",
         u"Continue stream processing even if no \"splice information stream\" is "
         u"found for the service. Without this information stream, we cannot remove "
         u"ads. By default, abort when the splice information stream is not found in "
         u"the PMT.");

    option(u"fix-cc", 'f');
    help(u"fix-cc",
         u"Fix continuity counters after removing splice-out/in sequences.");

    option(u"stuffing", 's');
    help(u"stuffing",
         u"Replace excluded packets with stuffing (null packets) instead "
         u"of removing them. Useful to preserve bitrate.");

    option(u"event-id", 0, INTEGER, 0, UNLIMITED_COUNT, 0, 31);
    help(u"event-id", u"id1[-id2]",
         u"Only remove splices associated with event ID's. Several --event-id options "
         u"may be specified.");

    option(u"dry-run", 'n');
    help(u"dry-run",
         u"Perform a dry run, report what operations would be performed. Use with --verbose.");
}


//----------------------------------------------------------------------------
// Get options method
//----------------------------------------------------------------------------

bool ts::ElementalPlugin::getOptions()
{
    getIntValue(_eventIDFilter, u"event-id-to-filter");
    duck.loadArgs(*this);
    _service.set(value(u""));
    _dropStatus = present(u"stuffing") ? TSP_NULL : TSP_DROP;
    _continue = present(u"continue");
    _adjustTime = present(u"adjust-time");
    _fixCC = present(u"fix-cc");
    getIntValues(_eventIDs, u"event-id");
    _dryRun = present(u"dry-run");
    return true;
}


//----------------------------------------------------------------------------
// Start method
//----------------------------------------------------------------------------

bool ts::ElementalPlugin::start()
{
    _tagsByPID.clear();
    _states.clear();
    _demux.reset();
    _videoPID = PID_NULL;
    _abort = false;


    _ccFixer.reset();
    _ccFixer.setGenerator(true);
    _ccFixer.setPIDFilter(NoPID);

    return true;
}


//----------------------------------------------------------------------------
// Constructor
//----------------------------------------------------------------------------

ts::ElementalPlugin::PIDState::PIDState(PID pid_) :
        pid(pid_),
        currentlyOut(false),
        outStart(INVALID_PTS),
        totalAdjust(0),
        lastPTS(INVALID_PTS),
        events(),
        immediateOut(false),
        immediateEventId(0),
        cancelImmediateOut(false),
        isAudio(false),
        isVideo(false),
        lastOutEnd(INVALID_PTS),
        ptsLastSeekPoint(INVALID_PTS),
        ptsBetweenSeekPoints(INVALID_PTS)
{
}


//----------------------------------------------------------------------------
// Invoked by the service discovery when the PMT of the service is available.
//----------------------------------------------------------------------------

void ts::ElementalPlugin::handlePMT(const PMT& pmt, PID)
{
    // We need to find a PID carrying splice information sections.
    bool foundSpliceInfo = false;

    // Analyze all components in the PMT.
    for (PMT::StreamMap::const_iterator it = pmt.streams.begin(); it != pmt.streams.end(); ++it) {

        const PID pid(it->first);
        const PMT::Stream& stream(it->second);

        if (stream.stream_type == ST_SCTE35_SPLICE) {
            // This is a PID carrying splice information.
            _demux.addPID(pid);
            PIDState& pidState(_states[pid]);
            pidState.immediateOut=0;
            foundSpliceInfo = true;
        }
    }


    // If we could not find any splice info stream, we cannot remove ads.
    if (!foundSpliceInfo) {
        // tsp->error(u"no splice information found in service %s, 0x%X (%d)", {_service.getName(), _service.getId(), _service.getId()});
        _abort = !_continue;
        return;
    }


}


//----------------------------------------------------------------------------
// Invoked by the demux when a splice information section is available.
//----------------------------------------------------------------------------

void ts::ElementalPlugin::handleSection(SectionDemux& demux, const Section& section)
{
    // Try to extract a SpliceInsert command from the section.
    SpliceInsert cmd;

    if (!SpliceInformationTable::ExtractSpliceInsert(cmd, section)) {
        // Not the right table or command, just ignore it.
        return;
    }

    std::cout << "pid, event_id, event_id_to_filter cancel: " << section.sourcePID() << " " <<cmd.event_id << " " << _eventIDFilter <<  " " << cmd.canceled << std::endl;
    // Either cancel or add the event.
    if (cmd.immediate) {
        if (cmd.event_id != _eventIDFilter){

            _states.find(500)->second.immediateOut=1;
            cmd.canceled=1;
            std::cout << _states.find(500)->second.immediateOut << std::endl;
        }

    }

    std::cout << "after pid, event_id, event_id_to_filter  cancel: " << section.sourcePID() << " " <<cmd.event_id << " "  << _eventIDFilter << " "<< cmd.canceled << std::endl;

}


//----------------------------------------------------------------------------
// Add a splicing event in a PID, from a SpliceInsert command.
//----------------------------------------------------------------------------

//----------------------------------------------------------------------------
// Remove all splicing events with specified id.
//----------------------------------------------------------------------------

void ts::ElementalPlugin::PIDState::cancelEvent(uint32_t event_id) {

}

//----------------------------------------------------------------------------
// Packet processing method
//----------------------------------------------------------------------------

ts::ProcessorPlugin::Status ts::ElementalPlugin::processPacket(TSPacket& pkt, TSPacketMetadata& pkt_data)
{
    const PID pid = pkt.getPID();
    Status pktStatus = TSP_OK;

    // Feed the various analyzers with the packet.
    _service.feedPacket(pkt);
    _demux.feedPacket(pkt);


    // Is this a PID which is subject to splicing?
    // Aquí sería audio o video

    if (pid==500){
        if (_states.find(500)->second.immediateOut==1){
            pktStatus = _dropStatus;
            std::cout << "Eliminando el evento "  << std::endl;
            _states.find(500)->second.immediateOut=0;
        }

    }

    // Abort if we now know that the service does not exist or in case or error.
    return _service.nonExistentService() || _abort ? TSP_END : pktStatus;
}